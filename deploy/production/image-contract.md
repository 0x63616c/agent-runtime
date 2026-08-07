# Production image contract

`deploy/production/Dockerfile` builds exactly two statically linked Linux
binaries from the reviewed root module:

- `/runtime` is the one role-composition binary. A Deployment selects exactly
  one `runtime serve --role=<role>` command and receives only that role's
  declared configuration and external Secret references.
- `/egress-proxy` is the separate finite-target model egress boundary.

The build uses digest-pinned Go and distroless base images. Before a Stack is
applied outside a disposable image build test, the operator must publish this
Dockerfile's output to its reviewed registry and replace the reference Stack's
deliberate placeholder with that immutable registry digest. Mutable tags and
an unreviewed locally built image are not production deployment evidence.
