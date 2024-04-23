package webrtc

import (
	prtc "github.com/pion/webrtc/v4"
)

type WebRTCIO struct {
	*prtc.PeerConnection
	SDP string
	// LocalSDP *sdp.SessionDescription
}

func (IO *WebRTCIO) GetAnswer() (string, error) {
	// Sets the LocalDescription, and starts our UDP listeners
	answer, err := IO.CreateAnswer(nil)
	if err != nil {
		return "", err
	}
	// IO.LocalSDP, err = answer.Unmarshal()
	// if err != nil {
	// 	return "", err
	// }
	gatherComplete := prtc.GatheringCompletePromise(IO.PeerConnection)
	if err := IO.SetLocalDescription(answer); err != nil {
		return "", err
	}
	<-gatherComplete
	return IO.LocalDescription().SDP, nil
}
