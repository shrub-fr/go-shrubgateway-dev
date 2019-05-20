# go-shrubgateway-dev

Shrub https subscheme implementation <https://shrub.fr/>

The command shrubgateway-dev starts a web server listening for TLS connections on the local host's loopback interface on port 58273, using the local CA at <user's home directory>/.shrubgateway

This server implements the protocol associated to the Shrub https subscheme, as defined in draft-shrub.fr-shrub at <https://github.com/shrub-fr/spec-shrub/blob/master/shrub.md>

However, the server tries to retrieve the application/branch file from the working directory first, before going to the network if the file is not found locally.
