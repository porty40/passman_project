# passman_project
## CLI-Based Password Manager

# Passman Installation Guide (Linux)

Follow the steps below to set up and run the **Passman** password manager application.

## 1. Check if Python is Installed (Python 3.9 Recommended) 
```bash
python --version
```

If Python is not installed, download and install it from the [official Python website](https://www.python.org/downloads/). 

## 2. Install `xclip` for Clipboard Interaction
```bash
sudo apt-get install xclip
```

## 3. Install `virtualenv`
```bash
pip install virtualenv
```

## 4. Create a Virtual Environment
```bash
python -m venv /path/to/venv
```

## 5. Navigate to the Virtual Environment Directory
```bash
cd /path/to/venv
```

## 6. Set Up the Application Folder (clone git repository)
  ```bash
  git clone https://github.com/username/passman.git
  ```

## 7. Activate the Virtual Environment
  ```bash
  source ./bin/activate
  ```

## 8. Install Dependencies
```bash
pip install -r requirements.txt
```

## 9. Run the Application
```bash
python3 passman.py
```
