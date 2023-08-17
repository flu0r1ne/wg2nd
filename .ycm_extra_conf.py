def Settings( **kwargs ):
	return {
		'flags': [
			'-Wall', '-Wextra', '-Werror',
			'-Isrc', '-Itest',
			'-std=c++20',
			'-Wno-unused-function',
		],
	}
