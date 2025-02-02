package webrtc

import (
	prtc "github.com/pion/webrtc/v4"
)

func RegisterCodecs(m *prtc.MediaEngine) error {
	for _, codec := range []prtc.RTPCodecParameters{
		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypePCMU, 8000, 0, "", nil},
			PayloadType:        0,
		},
		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypePCMA, 8000, 0, "", nil},
			PayloadType:        8,
		},
	} {
		if err := m.RegisterCodec(codec, prtc.RTPCodecTypeAudio); err != nil {
			return err
		}
	}
	videoRTCPFeedback := []prtc.RTCPFeedback{{"goog-remb", ""}, {"ccm", "fir"}, {"nack", ""}, {"nack", "pli"}}
	for _, codec := range []prtc.RTPCodecParameters{
		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=96", nil},
		// 	PayloadType:        97,
		// },

		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=98", nil},
		// 	PayloadType:        99,
		// },

		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=100", nil},
		// 	PayloadType:        101,
		// },
		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f", videoRTCPFeedback},
			PayloadType:        102,
		},
		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=102", nil},
		// 	PayloadType:        121,
		// },

		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f", videoRTCPFeedback},
			PayloadType:        127,
		},
		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=127", nil},
		// 	PayloadType:        120,
		// },

		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f", videoRTCPFeedback},
			PayloadType:        125,
		},
		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=125", nil},
		// 	PayloadType:        107,
		// },

		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f", videoRTCPFeedback},
			PayloadType:        108,
		},
		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=108", nil},
		// 	PayloadType:        109,
		// },

		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f", videoRTCPFeedback},
			PayloadType:        127,
		},
		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=127", nil},
		// 	PayloadType:        120,
		// },

		{
			RTPCodecCapability: prtc.RTPCodecCapability{prtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032", videoRTCPFeedback},
			PayloadType:        123,
		},
		// {
		// 	RTPCodecCapability: RTPCodecCapability{"video/rtx", 90000, 0, "apt=123", nil},
		// 	PayloadType:        118,
		// },
	} {
		if err := m.RegisterCodec(codec, prtc.RTPCodecTypeVideo); err != nil {
			return err
		}
	}
	return nil
}
