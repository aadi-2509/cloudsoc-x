"""
CloudSOC-X package setup.
"""
from setuptools import setup, find_packages

setup(
    name="cloudsoc-x",
    version="1.0.0",
    description="AWS-native Security Operations Center simulator and detection engine",
    author="Aaditya Modi",
    author_email="amodi22@asu.edu",
    python_requires=">=3.10",
    packages=find_packages(where="src") + find_packages(where="api"),
    package_dir={"": "src"},
    install_requires=[
        "boto3>=1.34.0",
        "requests>=2.31.0",
        "requests-aws4auth>=1.3.1",
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
        "python-dotenv>=1.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=8.1.1",
            "pytest-cov>=5.0.0",
            "pytest-mock>=3.14.0",
            "flake8>=7.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "cloudsoc-simulate=scripts.simulate_events:main",
            "cloudsoc-api=api.app:app",
        ]
    },
)
