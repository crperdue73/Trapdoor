FROM python:3.12-slim

WORKDIR /app
COPY shipper.py /app/shipper.py

# Nothing to install: stdlib only. Fewer moving parts in a security component
# is the point.
ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "/app/shipper.py"]
