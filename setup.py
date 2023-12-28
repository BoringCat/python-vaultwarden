from setuptools import setup

setup(
    name="python-vaultwarden",
    version="0.0.3",
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
        'cryptography>=41.0.5',
    ],
    python_requires='>=3',
)