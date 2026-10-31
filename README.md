# Akki LG Anywhere Remote

Private-use software for controlling an authorized, rooted LG webOS TV over a secured HTTPS relay. No external controller is required. The cloud relay runs on Render; the TV runs an outbound-only agent; a mobile browser provides the remote.

**Security**: Never expose the TV's LAN ports or publish phone/TV tokens or webOS pairing keys. Configure secrets only in Render environment variables and on the TV itself.

**Status**: In active development. The cloud service and TV agent are separately verified before automatic boot is enabled. Power-on from standby is not guaranteed.
