import click
import clickclick
import os
import stat
import re
import requests
import sys
import yaml
import bravado

from functools import partial
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from bravado_core.spec import Spec
from bravado.client import construct_request
from bravado.requests_client import RequestsClient

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'], obj={})

REPLACEABLE_COMMAND_CHARS = re.compile('[^a-z0-9]+')

SUBCOMMAND_LEVELS = 2  # Min 2


def normalize_command_name(s):
    '''
    >>> normalize_command_name('My Pets')
    'my-pets'

    >>> normalize_command_name('.foo.bar.')
    'foo-bar'
    '''
    return REPLACEABLE_COMMAND_CHARS.sub('-', s.lower()).strip('-')


def get_command_name(op):
    if op.http_method == 'get' and '{' not in op.path_name:
        return 'list'
    elif op.http_method == 'put':
        return 'update'
    else:
        return op.http_method


def invoke(op, ctx, *args, **kwargs):
    if op.http_method != 'get':
        clickclick.action('Invoking..')
    request = construct_request(op, {}, **kwargs)
    c = RequestsClient()
    c.session.verify = not ctx.obj['INSECURE']
    if ctx.obj['BASIC_AUTH'] is not None:
        from six.moves.urllib import parse as urlparse
        split = urlparse.urlsplit(op.swagger_spec.api_url)
        c.set_basic_auth(split.hostname, ctx.obj['BASIC_AUTH'][0], ctx.obj['BASIC_AUTH'][1])
    future = c.request(request)
    try:
        incoming_response = future.result()
        if op.http_method in ['get', 'list']:
            clickclick.action('Response: \n')
            clickclick.secho(incoming_response.text)
        clickclick.ok()
    except bravado.exception.HTTPError as e:
        clickclick.error(' ERROR: %s.' % e)


def sanitize_spec(spec):

    for path, path_obj in list(spec['paths'].items()):
        # remove root paths as no resource name can be found for it
        if path == '/':
            del spec['paths'][path]
    return spec


class OpenAPIClientCLI(click.Group):
    def list_commands(self, ctx):
        """
        Returns a list of subcommand names in the order they should appear.
        """
        if not self.commands and 'SPEC' in ctx.obj:
            self.commands = self.generate_cli(ctx)

        return sorted(self.commands)


    def get_command(self, ctx, name):
        """
        Given a context and a command name, this returns a :class:`Command`
        object if it exists or returns `None`.
        """
        if not self.commands and 'SPEC' in ctx.obj:
            self.commands = self.generate_cli(ctx)

        return self.commands.get(name)


    def generate_command(self, ctx, op):
        """
        Generate and return a Click command.

        NOTE: To have a constent CLI, parameters need to be ordered.  Path
              parameters keep the order in which they appear in the path.  Then
              is following other parameters, sorted alphabetically.
        """
        params = []
        cmd_help = ''
        cmd = click.Command(get_command_name(op),
                            callback=partial(invoke, op=op, ctx=ctx),
                            short_help=op.op_spec.get('summary'))

        # First, handle path parameters.
        for p in op.path_name.split('/'):
            if not p.startswith('{'):
                continue

            param_name = p[1:-1]
            cmd.params.append(click.Argument([param_name, param_name]))
            param_desc = op.params[param_name].param_spec.get('description',
                                                'No description available.')
            cmd_help += '%s: %s\n\n' % (param_name.upper(), param_desc)

        # Then, handle other parameters.
        for param_name, param in op.params.items():
            if param.param_spec.get('in', '') == 'path':
                continue

            if param.required:
                arg = click.Argument([param.name, param.name])
                params.append(arg)
                param_desc = param.param_spec.get('description',
                                                  'No description available.')
                cmd_help = cmd_help + '%s: %s\n\n' % (param.name.upper(), param_desc)
            else:
                arg = click.Option(['--' + param.name])
                params.append(arg)

        if params:
            params.sort(key=lambda param: param.name)
            cmd.params.extend(params)
        cmd.help = cmd_help

        return cmd


    def generate_cli(self, ctx):
        """
        Generate all commands for the API specification.
        """
        spec = ctx.obj['SPEC']
        commands = {}

        def all_spec_op(spec):
            """
            Iterate through all operations of the specification, eliminating
            duplicates.
            """
            processed_paths = []
            for res_name, res in spec.resources.items():
                for key, op in res.operations.items():
                    path = op.path_name + '/' + get_command_name(op)
                    if path in processed_paths:
                        continue
                    processed_paths.append(path)
                    yield op

        # Get all operations and sort them by path.
        all_op = [ op for op in all_spec_op(spec) ]
        all_op.sort(key=lambda op: op.path_name)

        group_stack = []
        cur_path = '/'

        for op in all_op:
            # Translate the real path to a command hierarchy.
            # Ex: With 2 subcommand levels, the real path
            #   '/users/{name}/pref/something'
            # is translated to:
            #   '/users/pref-something'
            path = op.path_name
            # 1) Remove parameters from path.
            path = re.sub(r'{[^{}]+}', '', path)
            # 2) Normalize the path.
            path = os.path.normpath(path)
            # 3) Split the according to the number of subcommand levels and then
            #    normalize parts as command names, before rebuilding a full
            #    path.
            path = '/' + '/'.join([ normalize_command_name(p) for p in path[1:].split('/', SUBCOMMAND_LEVELS - 1) ])

            # Handle the relative path to the new path, calculated from the
            # previous one.
            path_parts = os.path.relpath(path, cur_path).split('/')
            for i, p in enumerate(path_parts):
                if p == '..':
                    # Moved back in the path: Pop group from stack.
                    group_stack.pop()
                elif p == '.':
                    # Same path: No group to handle.
                    pass
                else:
                    # Moved forward in the path: Create group and push it to
                    # stack.
                    group_name = p
                    group = click.Group(group_name, short_help='Manage {}'.format(group_name))
                    if len(group_stack) == 0:
                        commands[group_name] = group
                    else:
                        group_stack[-1].add_command(group)
                    group_stack.append(group)

                # Add command if we are at the end of the path.
                if i == len(path_parts) - 1:
                    command_name = get_command_name(op)
                    group_stack[-1].add_command(self.generate_command(ctx, op))

            # Save the current path.
            cur_path = path

        return commands


def openapi_spec_callback(ctx, param, value):
    spec = value
    origin_url = None
    if spec.startswith('https://') or spec.startswith('http://'):
        origin_url = spec
        try:
            verify = not ctx.obj.get('INSECURE', False)
            r = requests.get(spec, verify=verify)
            r.raise_for_status()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise click.BadParameter(('failed to fetch OpenAPI specification '
                                      'at \'%s\'.\nDetails: %s.') % (spec, e))
        try:
            spec = yaml.safe_load(r.text)
        except (yaml.reader.ReaderError, yaml.scanner.ScannerError) as e:
            raise click.BadParameter('invalid OpenAPI specification at '
                                     '\'%s\'.\nDetails: %s.' % (spec, e))
    else:
        try:
           st = os.stat(spec)
        except OSError:
            raise click.BadParameter('%s does not exist.' % spec)
        if not stat.S_ISREG(st.st_mode):
            raise click.BadParameter('%s is not a file.' % spec)
        if not os.access(spec, os.R_OK):
            raise click.BadParameter('%s is not readable.' % spec)

        with open(spec, 'rb') as fd:
            try:
                spec = yaml.safe_load(fd.read())
            except (yaml.reader.ReaderError, yaml.scanner.ScannerError) as e:
                raise click.BadParameter('%s is not a valid OpenAPI '
                                         'specification.\nDetails: %s.' % (spec, e))

    spec = sanitize_spec(spec)
    spec = Spec.from_dict(spec, origin_url=origin_url)

    ctx.obj['SPEC'] = spec
    return value


def basic_auth_arg_callback(ctx, param, value):
    new_value = None
    if value:
        credentials = value.split(':', 1)
        user = credentials[0]
        password = credentials[1] if len(credentials) == 2 else ''

        if password.startswith('/'):
            import os.path
            if os.path.isfile(password):
                with open(password, 'r') as pass_file:
                    password = pass_file.read().splitlines()[0]

        new_value = [user, password]

    ctx.obj['BASIC_AUTH'] = new_value
    return new_value


def save_arg_callback(ctx, param, value):
    ctx.obj[param.name.upper()] = value
    return value


@click.command(cls=OpenAPIClientCLI, context_settings=CONTEXT_SETTINGS)
@click.argument('OPENAPI_SPEC', callback=openapi_spec_callback)
@click.option('-i', '--insecure', is_flag=True, callback=save_arg_callback,
              help=('Don\'t check the server certificate against the '
                    'available certificate authorities.  Also don\'t require '
                    'the URL host name to match the common name presented by '
                    'the certificate.'))
@click.option('-b', '--basic-auth', nargs=1, metavar='<user:password>',
              callback=basic_auth_arg_callback,
              help=('Specify the user name and password to use for server HTTP '
                    'basic authentication.  Password can be an absolute path '
                    'to an existing file containing the password.'))
@click.pass_context
def main(ctx, openapi_spec, insecure, basic_auth):
    """
    Python command line client for REST APIs defined with OpenAPI-Spec/Swagger-Spec.

    The OpenAPI specification is provided by the OPENAPI_SPEC argument and must
    be in JSON format.  The argument can be the path of a file or an URL where
    the specification can be fetched.
    """
    pass
