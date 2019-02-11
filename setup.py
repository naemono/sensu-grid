from setuptools import setup

setup(
    name='sensugrid',
    packages=['sensugrid'],
    include_package_data=True,
    install_requires=[
        'flask',
        'pyyaml',
        'gunicorn',
        'requests'
    ],
)
