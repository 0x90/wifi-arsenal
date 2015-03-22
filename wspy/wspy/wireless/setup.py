from distutils.core import setup, Extension
setup(name="wireless", version="1.0",
      ext_modules=[Extension("wireless", ["wireless.c", "iwlib.c"])])
