# Django Rest Framewrok Custom Authentication

Login with Email rather than username and custom User Registration, Login, Logout, Change Password and Reset Password using email link.

## Prerequisites:

You will need the following programmes properly installed on your computer.

* [Python](https://www.python.org/) 3.5+

* Virtual Environment

To install virtual environment on your system use:

apt-get install python3-venv

## Installation and Running :

```bash
git clone https://github.com/ongraphpythondev/django_custom_auth.git

cd django_custom_auth

python3 -m venv venv

source venv/bin/activate

# install required packages for the project to run
pip install -r requirements.txt

python manage.py migrate

python manage.py runserver
```

