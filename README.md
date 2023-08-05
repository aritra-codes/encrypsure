# Encrypsure

#### This is my submission for the final project of CS50P 💻.

#### Encrypsure is a command-line password managing application which gives you the freedom to forget your passwords with confidence. Using this application, you can view, create, edit, and delete numerous password entries. When viewing entries, you can view either all entries or filter by service and username to find the exact entry you are looking for. When creating an entry, you can just paste the website link as the service and it will automatically deduce the name of the service. Using the autopass feature, you can automatically create a strong 16-character password, which will definitely give the hackers trying to break into your accounts a difficult time. To top it all of, you can also set a master password, so no one except you can view your precious passwords. Keep your passwords safe and secure 🔒!

---

## Installation

You must have [python](https://www.python.org/) installed to run this application.

Firstly, clone the repository.

Then, change directories into the newly cloned repository:

```
$ cd encrypsure
```

Finally, using [pip](https://pip.pypa.io/en/stable/), install the application dependencies:

```
$ pip3 install -r requirements.txt
```

---

## Usage

To run the application:

```
$ python3 project.py [-h] [-c] [-e] [-d] [-ap] [-a] [service] [username]
```

<br>

For further help running the application:

```
$ python3 project.py --help
```
