from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="ttpnav",
    version="0.1.2",
    author="Joseph Fisher",
    author_email="jfisher@cyntel.com",
    description="A package to navigate MITRE ATT&CK data easily.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fish-not-phish/ttpnav",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'mitreattack-python'
    ],
)
