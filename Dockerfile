# Gunakan gambar Python 3.10 slim resmi sebagai gambar dasar
FROM python:3.10-slim

# Tetapkan variabel lingkungan PYTHONUNBUFFERED ke True
ENV PYTHONUNBUFFERED True

# Tetapkan variabel lingkungan APP_HOME ke /app
ENV APP_HOME /app

# Tetapkan direktori kerja di dalam kontainer ke /app
WORKDIR $APP_HOME

# Salin semua konten dari direktori saat ini ke dalam kontainer di /app
COPY . ./

# Instal dependensi yang tercantum dalam requirements.txt
RUN pip install -r requirements.txt

# Tetapkan CMD untuk menjalankan gunicorn dan melayani aplikasi Flask
CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 0 app:app
