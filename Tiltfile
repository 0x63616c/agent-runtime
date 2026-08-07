# The only local topology starts from the typed Stack renderer. This file owns
# no infrastructure schema and is intentionally locked to OrbStack.
allow_k8s_contexts('orbstack')
config.define_string('stack', usage='sole local Stack identity')
cfg = config.parse()
stack = cfg.get('stack', '')

if not stack:
    fail('pass -- --stack=<lowercase-dns-label>')
if len(stack) > 40 or stack[0] == '-' or stack[-1] == '-':
    fail('--stack must be a lowercase DNS label up to 40 characters')
stack_remainder = stack
for allowed in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-']:
    stack_remainder = stack_remainder.replace(allowed, '')
if stack_remainder:
    fail('--stack must be a lowercase DNS label up to 40 characters')
if k8s_context() != 'orbstack':
    fail('agent-runtime local development only permits the explicit orbstack context')

stack_file = '.runtime/dev/' + stack + '.stack.json'
local('go run ./tools/dev render --stack=' + stack + ' --output=' + stack_file, quiet=True)
stack_manifests = local('go run ./cmd/stackctl manifests --stack-file ' + stack_file + ' --profile local', quiet=True)
secret_manifests = local('go run ./tools/dev secrets --stack=' + stack + ' --root=.', quiet=True)
k8s_yaml([stack_manifests, secret_manifests])

for role in ['api', 'worker', 'codec']:
    docker_build('agent-runtime-dev/' + stack + '/' + role, '.', dockerfile='deploy/dev/Dockerfile', only=['cmd/dev-role', 'deploy/dev/Dockerfile', 'go.mod', 'go.sum'])

k8s_resource('postgres', pod_readiness='wait')
k8s_resource('temporal', resource_deps=['postgres'], pod_readiness='wait')
k8s_resource('temporal-ui', resource_deps=['temporal'], links=[link('http://temporal-ui:8080', 'Temporal UI')])
k8s_resource('blob', pod_readiness='wait')
k8s_resource('telemetry', pod_readiness='wait')
k8s_resource('api', resource_deps=['postgres', 'temporal', 'blob', 'telemetry'], links=[link('http://api:8080/healthz', 'API health')])
k8s_resource('worker', resource_deps=['postgres', 'temporal', 'blob', 'telemetry'])
k8s_resource('codec', resource_deps=['blob', 'temporal'], links=[link('http://codec:8082/healthz', 'Codec health'), link('https://0x63616c.github.io/agent-runtime/', 'Agent Runtime docs')])
