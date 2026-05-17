package api

import "github.com/gin-gonic/gin"

func (s *Server) registerPlusManagementRoutes(mgmt *gin.RouterGroup) {
	mgmt.GET("/codex-device-auth-url", s.mgmt.RequestCodexDeviceToken)
	mgmt.GET("/codebuddy-auth-url", s.mgmt.RequestCodeBuddyToken)
	mgmt.GET("/kiro-portal-auth-url", s.mgmt.RequestKiroPortalToken)
	mgmt.GET("/kiro-aws-authcode-auth-url", s.mgmt.RequestKiroAWSAuthCodeToken)
	mgmt.GET("/kiro-idc-auth-url", s.mgmt.RequestKiroIDCToken)
	mgmt.POST("/kiro-import", s.mgmt.ImportKiroToken)
}
