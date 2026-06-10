# Chef execution image for ContainerSandbox.
#
# The chef (chef_main.py) is STANDALONE — it needs only a Python interpreter
# and `cryptography`. ContainerSandbox bind-mounts chef_main.py, the public
# key, and the kitchen fixtures read-only at runtime, so this image carries NO
# source and NO data: it is just the runtime. That keeps the image tiny and
# means the code that runs is always the host's current chef, mounted read-only.
#
# Build:   docker build -t sentinel-chef .
# Used by: ContainerSandbox(image="sentinel-chef", runtime="runsc" for gVisor)
#
# The container runs as a non-root uid passed by ContainerSandbox (--user),
# with no network, all caps dropped, read-only rootfs, and a tmpfs cwd.
FROM python:3.12-slim

RUN pip install --no-cache-dir "cryptography>=42.0"

# Bytecode writing is pointless on a read-only rootfs; silence it.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# No ENTRYPOINT/USER: ContainerSandbox supplies the exact command
# (python /chef/chef_main.py ...) and the --user mapping at run time.
