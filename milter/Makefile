#
# Mostly I want to run tests easily.

# MODORDER is the order that modules must be tested in in order to stop
# as soon as we have a failure, and not cause cascades.
MODORDER=codec convo
tests:
	for i in ${MODORDER}; do echo $$i; python test_$$i.py || exit 1; done

# Current versions of pychecker appear to choke on 'pychecker *.py'.
# Oh well.
pychecker:
	for i in *.py; do pychecker $$i; done

clean:
	rm -f *.pyc *~
