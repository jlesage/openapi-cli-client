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
from bravado_core.spec import Spec
from bravado.client import construct_request
from bravado.requests_client import RequestsClient

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'], obj={})

REPLACEABLE_COMMAND_CHARS = re.compile('[^a-z0-9]+')


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


class OpenAPIClientCLI(click.MultiCommand):
    def list_commands(self, ctx):
        commands = []
        if 'SPEC' in ctx.obj:
            for res_name, res in ctx.obj['SPEC'].resources.items():
                commands.append(normalize_command_name(res_name))

        return commands


    def get_command(self, ctx, name):
        for res_name, res in ctx.obj['SPEC'].resources.items():
            if name == normalize_command_name(res_name):
                return self.gen_command_grp_from_spec(ctx, res_name, res)

        return None


    def gen_command_grp_from_spec(self, ctx, res_name, res):
        grp = clickclick.AliasedGroup(normalize_command_name(res_name), short_help='Manage {}'.format(res_name))
        for op_name, op in res.operations.items():
            name = get_command_name(op)

            cmd = click.Command(name, callback=partial(invoke, op=op, ctx=ctx), short_help=op.op_spec.get('summary'))
            for param_name, param in op.params.items():
                if param.required:
                    arg = click.Argument([param.name])
                    cmd.params.append(arg)
                else:
                    arg = click.Option(['--' + param.name])
                    cmd.params.append(arg)

            grp.add_command(cmd)
        return grp


def openapi_spec_callback(ctx, param, value):
    spec = value
    origin_url = None
    if spec.startswith('https://') or spec.startswith('http://'):
        origin_url = spec
        try:
            r = requests.get(spec)
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


@click.command(cls=OpenAPIClientCLI, context_settings=CONTEXT_SETTINGS)
@click.argument('OPENAPI_SPEC', callback=openapi_spec_callback)
@click.pass_context
def main(ctx, openapi_spec):
    """
    Python command line client for REST APIs defined with OpenAPI-Spec/Swagger-Spec.

    The OpenAPI specification is provided by the OPENAPI_SPEC argument and must
    be in JSON format.  The argument can be the path of a file or an URL where
    the specification can be fetched.
    """
    pass

