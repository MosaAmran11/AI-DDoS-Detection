# Extract all CSV files
import zipfile

zip_path = "/content/drive/MyDrive/CSV-03-11.zip"
extract_path = "/content/drive/MyDrive/ddos_dataset"

with zipfile.ZipFile(zip_path, 'r') as zip_ref:
    zip_ref.extractall(extract_path)
