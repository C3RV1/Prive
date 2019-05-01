from setuptools import setup, find_packages

setup(name='PriveAPI',
      version='0.1',
      description='API to create programs compatible with Prive',
      keywords='prive',
      url='http://github.com/c3rv1/Prive',
      author='KeyFr4me',
      author_email='cervilla.alex@gmail.com',
      license='GNU General Public License v3.0',
      packages=find_packages(),
      install_requires=[
          'pycrypto==2.6.1',
      ])
