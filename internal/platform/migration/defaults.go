package migration

func Default() []Migration {
	return []Migration{
		{Version: 1, Name: "initial_owndock_schema", Up: createInitialOwnDockSchema},
	}
}
