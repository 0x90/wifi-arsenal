from setuptools import setup, find_packages

setup(
    name='Watcher',
    author='catalyst256',
    version='1.0',
    author_email='catalyst256@gmail.com',
    description='Maltego with a twist of wireless',
    license='GPL',
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    zip_safe=False,
    package_data={
        '' : [ '*.gif', '*.png', '*.conf', '*.mtz', '*.machine' ] # list of resources
    },
    install_requires=[
        'canari>=0.8',
        'request>=2.0.1'
    ],
    dependency_links=[
        # custom links for the install_requires
    ]
)
