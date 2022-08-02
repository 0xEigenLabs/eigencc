all:
	@cargo vendor > config
	@./lic.py | sort  > licenses.txt
test:
	@cargo vendor > config
clean:
	@rm -rf vendor
	@rm -rf Cargo.lock
