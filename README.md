## Tidal pull

Pulls Tidal artists, albums, songs into Obsidian-flavored markdown notes.

That was the idea, anyway. But it's turned out not to be worth the time. I thought it would be an easy "just plug in the API key and make a request!", but OAuth2 is a lot more complicated than that. Especially when run from the command-line, where, for example, you need to spin up a local web server from within the script to intercept the information returned via redirects (which this script does successfully).

However, I hit an insurmountable problem after getting through all the OAuth2 hoops: the scopes documented by Tidal (or used in the web player? I can't remember) that would be useful for my purposes (`collection.read`, `playlists.read`, `collection.write`, `playlists.write`) aren't supported for 3rd party API clients, contrary to what I was led to believe from reading their documentation. I found this out the hard way.

I considered raising the issue with Tidal, but this script has limited utility to me anyway, and was originally meant as a small half-day project. And it would seem that Tidal did _not_ design their API with having people scrape their own data in mind, so even if I were to successfully complete this, I don't want to run afowl their TOS or get one of those scary letters in the mail.

But it was a nice crash course in real-world OAuth2, and may be of use to someone trying to implement something similar.
