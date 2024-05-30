run:
	@go run .

push:
	@git add .
	@git commit -m "$(commit)"
	@git branch $(branch)
	@git checkout $(branch)
	@git push -u origin $(branch)