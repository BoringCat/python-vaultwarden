from setuptools import setup, find_packages

setup(
    name="python-vaultwarden",
    version="0.0.1",
    author="BoringCat",
    author_email="c654477757@gmail.com",
    description="Simple VaultWarden API for Python",
    url="https://github.com/BoringCat/python-vaultwarden",
    packages=["vaultwarden"],
    package_dir={
        "vaultwarden": "vaultwarden"
    },

    install_requires = [
        'requests>=2.27.1',
        'passlib>=1.7.4',
        'hkdf>=0.0.3',
        'pycrypto>=2.6.1',
    ],
    python_requires='>=3, <3.10',
)