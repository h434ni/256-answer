FROM python:3.12-alpine
WORKDIR /app
COPY solution.py /app/solution.py
ENTRYPOINT ["python3","/app/solution.py"]
