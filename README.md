# Asphalt
Asphalt is a client for the Runway protocol. It utilizes OpenMLS for its MLS implementation.
<p float="left">
  <img src="https://raw.githubusercontent.com/runwayproject/asphalt/refs/heads/main/screenshot.png" width="1000" />
</p>
## Running the desktop app
Install the frontend dependencies once:

```
npm install
```

Start the desktop client (this assumes the server is running on 127.0.0.1:32767)
```powershell
npm run tauri:dev -- 127.0.0.1:32767
```
