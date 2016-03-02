RESULTS ?= reports

# run this in parallel!! -j is your friend
all: fake_check

fake_check: fake_check.py
	mkdir -p $(RESULTS)
	./$(<) > ${RESULTS}/$(@).xml

clean:
	rm -rf $(RESULTS)
