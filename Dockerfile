FROM python:3.9-slim
WORKDIR /app
COPY portal/ /app/
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]