# TRAPDOOR console. stdlib only, so there is no build step to rot.
#
# Deliberately not the nginx image: the decoy must stay a plain static server,
# and the console must not be able to grow into something that serves content
# from web/html. Separate images keep that true.
FROM python:3.12-alpine

WORKDIR /app
COPY server.py /app/server.py
# The banner and logo the README shows at the top. Resized once at build time
# from the 1.8 MB source PNG: a dashboard should not ship a 2 MB image to the
# browser on every cold load. Static assets live in the image so the console
# has no dependency on the host filesystem for its own appearance.
COPY static/banner.jpg /static/banner.jpg
COPY static/logo.png /static/logo.png

# Unprivileged. It only reads files; it has no reason to be root.
RUN adduser -D -H -u 10001 console
USER console

ENV CONSOLE_BIND=0.0.0.0 \
    CONSOLE_PORT=8081 \
    OUT_DIR=/out \
    VERIFY_DIR=/verify \
    CONSOLE_STATIC=/static \
    PYTHONUNBUFFERED=1

EXPOSE 8081

# /healthz answers 200 without touching the log, so a failing events file
# does not get reported as a dead console. Those are different failures.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8081/healthz',timeout=2).status==200 else 1)"

ENTRYPOINT ["python3", "/app/server.py"]
