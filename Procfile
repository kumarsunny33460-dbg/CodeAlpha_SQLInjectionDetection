web: gunicorn --config deploy/gunicorn.conf.py wsgi:application
release: python -c "import compileall,sys; sys.exit(0 if compileall.compile_dir('sqlshield', quiet=1) else 1)"
