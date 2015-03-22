
try: Tabloid
except:
	class Tabloid:

		def __call__(self):
			return self

Tabloid = Tabloid()
