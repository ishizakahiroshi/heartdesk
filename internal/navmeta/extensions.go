package navmeta

// RegisterCard is used only during app.New, before requests can read registries.
// The caller validates the entire extension set before the first registration.
func RegisterCard(meta MonitorCardMeta, label, group string, order int, screens, capabilities []string, component string) {
	monitorCardRegistry = append(monitorCardRegistry, meta)
	sharedLabelByID[meta.ID] = label
	defaultCardNav[meta.ID] = cardNav{Group: group, Order: order}
	if len(screens) == 0 {
		screens = []string{"monitor"}
	}
	cardScreens[meta.ID] = append([]string(nil), screens...)
	cardRequiredCapabilities[meta.ID] = append([]string(nil), capabilities...)
	if component != "" {
		cardRequiredComponents[meta.ID] = component
	}
}
