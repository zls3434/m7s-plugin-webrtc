package webrtc

import (
	"fmt"
	"time"

	"github.com/pion/rtcp"
	. "github.com/pion/webrtc/v3"
	"go.uber.org/zap"
	. "m7s.live/engine/v4"
	. "m7s.live/engine/v4/track"
)

type WebRTCPublisher struct {
	Publisher
	WebRTCIO
}

func (puber *WebRTCPublisher) OnEvent(event any) {
	switch event.(type) {
	case IPublisher:
		puber.OnTrack(puber.onTrack)
	}
	puber.Publisher.OnEvent(event)
}

func (puber *WebRTCPublisher) onTrack(track *TrackRemote, receiver *RTPReceiver) {
	puber.Info("onTrack", zap.String("kind", track.Kind().String()), zap.Uint8("payloadType", uint8(track.Codec().PayloadType)))
	if codec := track.Codec(); track.Kind() == RTPCodecTypeAudio {
		if puber.AudioTrack == nil {
			switch codec.PayloadType {
			case 8:
				puber.AudioTrack = NewG711(puber.Stream, true)
			case 0:
				puber.AudioTrack = NewG711(puber.Stream, false)
			default:
				puber.AudioTrack = nil
				return
			}
		}
		for {
			rtpItem := puber.AudioTrack.GetRTPFromPool()
			if i, _, err := track.Read(rtpItem.Value.Raw[:1460]); err == nil {
				rtpItem.Value.Unmarshal(rtpItem.Value.Raw[:i])
				puber.AudioTrack.WriteRTP(rtpItem)
			} else {
				puber.Info("track stop", zap.String("kind", track.Kind().String()), zap.Error(err))
				rtpItem.Recycle()
				return
			}
		}
	} else {
		go puber.writeRTCP(track)
		if puber.VideoTrack == nil {
			puber.VideoTrack = NewH264(puber.Stream, byte(codec.PayloadType))
		}
		for {
			rtpItem := puber.VideoTrack.GetRTPFromPool()
			if i, _, err := track.Read(rtpItem.Value.Raw[:1460]); err == nil {
				rtpItem.Value.Unmarshal(rtpItem.Value.Raw[:i])
				puber.VideoTrack.WriteRTP(rtpItem)
			} else {
				puber.Info("track stop", zap.String("kind", track.Kind().String()), zap.Error(err))
				rtpItem.Recycle()
				return
			}
		}
	}
}

func (puber *WebRTCPublisher) writeRTCP(track *TrackRemote) {
	ticker := time.NewTicker(webrtcConfig.PLI)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if rtcpErr := puber.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(track.SSRC())}}); rtcpErr != nil {
				fmt.Println(rtcpErr)
			}
		case <-puber.Done():
			return
		}
	}
}
