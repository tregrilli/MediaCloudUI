# MediaCloudUI
cloud interface for mediaserver managment and access control

## Configuration

The Flask app queries Oven Media Engine's REST API (`/v1`). If the API is
protected with basic authentication, set the following environment variables or
rely on their defaults:

- `OME_API_URL` (default `http://localhost:8081/v1/stream`)
- `OME_API_USER` (default `user`)
- `OME_API_PASS` (default `pass`)

These values correspond to the `<AccessToken>` configured in OME's
`Server.xml`. `OME_API_URL` should point to the stream discovery endpoint and
the application will automatically derive the base API path (ending in `/v1/`)
to query additional resources such as:

- `/stats/current/vhosts/<vhost>/apps/<app>` – application-level statistics
- `/stats/current/vhosts/<vhost>/apps/<app>/streams/<stream>` – per-stream statistics
- `/vhosts/<vhost>/apps/<app>/streams` – list of available streams


## Pages

- `/streams` – lists discovered streams and plays them via OvenPlayer.
- `/info` – shows application stats and per-stream metrics.

