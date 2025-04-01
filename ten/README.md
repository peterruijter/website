# README
This document briefly describes how to use this package.

## How to use
1. Extract the package on a location on your host account `tar -xzf ./tentacles-1.4.1.tgz` and make sure the files are accessible via your website.
2. Update the following lines in the header of your website:
```
<script type="text/javascript">
  window.tentacles = {
    apiToken: '{API_TOKEN}',
    installUri: 'https://YOUR.DOMAIN/PATH/TO/tentacles-1.4.1/'
  };
</script>
<script type="text/javascript" src="{/PATH/TO/}tentacles-1.4.1/tentacle.js"></script>
```
3. Replace {API_TOKEN} and {/PATH/TO/} with the correct values.
4. Make sure the tentacles.smartocto.com domain is accessible from your website.


## How to test
1. Request the page on which you have installed the tentacles script.
2. Open the browser console and check if the tentacles script is loaded.
3. Check if the `tentacle.js` script is loaded from your host by checking the network tab of the browser console.
4. Check if a request is made to `https://ingestion.smartocto.com/t`.
5. Check if the Tentacles dock is loaded when you activate it via a browser plugin or the prepared link you can find at https://smartocto.com/tentacles/
6. All is set, have fun!
