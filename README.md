# MediaCloudUI
cloud interface for mediaserver managment and access control

## Configuration

The Flask app queries Oven Media Engine's REST API. If the API is protected
with basic authentication, set the following environment variables or rely on
their defaults:

- `OME_API_URL` (default `http://localhost:8081/v1/stream`)
- `OME_API_USER` (default `user`)
- `OME_API_PASS` (default `pass`)

These values correspond to the `<AccessToken>` configured in OME's
`Server.xml`.
