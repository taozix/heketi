//
// Copyright (c) 2015 The heketi Authors
//
// This file is licensed to you under your choice of the GNU Lesser
// General Public License, version 3 or any later version (LGPLv3 or
// later), or the GNU General Public License, version 2 (GPLv2), in all
// cases as published by the Free Software Foundation.
//

package cmds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/heketi/heketi/pkg/glusterfs/api"
	"github.com/spf13/cobra"
)

var (
	size                 int
	volname              string
	durability           string
	replica              int
	disperseData         int
	redundancy           int
	gid                  int64
	snapshotFactor       float64
	clusters             string
	expandSize           int
	id                   string
	glusterVolumeOptions string
	block                bool
)

func init() {
	RootCmd.AddCommand(volumeCommand)
	volumeCommand.AddCommand(volumeCreateCommand)
	volumeCommand.AddCommand(volumeDeleteCommand)
	volumeCommand.AddCommand(volumeExpandCommand)
	volumeCommand.AddCommand(volumeInfoCommand)
	volumeCommand.AddCommand(volumeListCommand)
	volumeCommand.AddCommand(volumeBlockHostingRestrictionCommand)
	volumeBlockHostingRestrictionCommand.AddCommand(volumeBlockHostingRestrictionUnlockCommand)
	volumeBlockHostingRestrictionCommand.AddCommand(volumeBlockHostingRestrictionLockCommand)
	volumeCommand.AddCommand(volumeEndpointCommand)
	volumeEndpointCommand.AddCommand(volumeEndpointPatchCommand)

	volumeCreateCommand.Flags().IntVar(&size, "size", 0,
		"\n\tSize of volume in GiB")
	volumeCreateCommand.Flags().Int64Var(&gid, "gid", 0,
		"\n\tOptional: Initialize volume with the specified group id")
	volumeCreateCommand.Flags().StringVar(&volname, "name", "",
		"\n\tOptional: Name of volume. Only set if really necessary")
	volumeCreateCommand.Flags().StringVar(&durability, "durability", "replicate",
		"\n\tOptional: Durability type.  Values are:"+
			"\n\t\tnone: No durability.  Distributed volume only."+
			"\n\t\treplicate: (Default) Distributed-Replica volume."+
			"\n\t\tdisperse: Distributed-Erasure Coded volume.")
	volumeCreateCommand.Flags().IntVar(&replica, "replica", 3,
		"\n\tReplica value for durability type 'replicate'.")
	volumeCreateCommand.Flags().IntVar(&disperseData, "disperse-data", 4,
		"\n\tOptional: Dispersion value for durability type 'disperse'.")
	volumeCreateCommand.Flags().IntVar(&redundancy, "redundancy", 2,
		"\n\tOptional: Redundancy value for durability type 'disperse'.")
	volumeCreateCommand.Flags().Float64Var(&snapshotFactor, "snapshot-factor", 1.0,
		"\n\tOptional: Amount of storage to allocate for snapshot support."+
			"\n\tMust be greater 1.0.  For example if a 10TiB volume requires 5TiB of"+
			"\n\tsnapshot storage, then snapshot-factor would be set to 1.5.  If the"+
			"\n\tvalue is set to 1, then snapshots will consume the storage allocated")
	volumeCreateCommand.Flags().StringVar(&clusters, "clusters", "",
		"\n\tOptional: Comma separated list of cluster ids where this volume"+
			"\n\tmust be allocated. If omitted, Heketi will allocate the volume"+
			"\n\ton any of the configured clusters which have the available space."+
			"\n\tProviding a set of clusters will ensure Heketi allocates storage"+
			"\n\tfor this volume only in the clusters specified.")
	volumeCreateCommand.Flags().StringVar(&glusterVolumeOptions, "gluster-volume-options", "",
		"\n\tOptional: Comma separated list of volume options which can be set on the volume."+
			"\n\tIf omitted, Heketi will set no volume option for the volume.")
	volumeExpandCommand.Flags().IntVar(&expandSize, "expand-size", 0,
		"\n\tAmount in GiB to add to the volume")
	volumeExpandCommand.Flags().StringVar(&id, "volume", "",
		"\n\tId of volume to expand")
	volumeCreateCommand.Flags().BoolVar(&block, "block", false,
		"\n\tOptional: Create a block-hosting volume. Intended to host"+
			"\n\tloopback files to be exported as block devices.")
	volumeCreateCommand.SilenceUsage = true
	volumeDeleteCommand.SilenceUsage = true
	volumeExpandCommand.SilenceUsage = true
	volumeInfoCommand.SilenceUsage = true
	volumeListCommand.SilenceUsage = true
	volumeBlockHostingRestrictionCommand.SilenceUsage = true
	volumeEndpointCommand.SilenceUsage = true
	volumeEndpointPatchCommand.SilenceUsage = true

	volumeCommand.AddCommand(volumeCloneCommand)
	volumeCloneCommand.Flags().StringVar(&volname, "name", "",
		"\n\tOptional: Name of the newly cloned volume.")
	volumeCloneCommand.SilenceUsage = true
}

var volumeCommand = &cobra.Command{
	Use:   "volume",
	Short: "Heketi Volume Management",
	Long:  "Heketi Volume Management",
}

var volumeCreateCommand = &cobra.Command{
	Use:   "create",
	Short: "Create a GlusterFS volume",
	Long:  "Create a GlusterFS volume",
	Example: `  * Create a 100GiB replica 3 volume:
      $ heketi-cli volume create --size=100

  * Create a 100GiB replica 3 volume specifying two specific clusters:
      $ heketi-cli volume create --size=100 \
        --clusters=0995098e1284ddccb46c7752d142c832,60d46d518074b13a04ce1022c8c7193c

  * Create a 100GiB replica 2 volume with 50GiB of snapshot storage:
      $ heketi-cli volume create --size=100 --snapshot-factor=1.5 --replica=2

  * Create a 100GiB distributed volume
      $ heketi-cli volume create --size=100 --durability=none

  * Create a 100GiB erasure coded 4+2 volume with 25GiB snapshot storage:
      $ heketi-cli volume create --size=100 --durability=disperse --snapshot-factor=1.25

  * Create a 100GiB erasure coded 8+3 volume with 25GiB snapshot storage:
      $ heketi-cli volume create --size=100 --durability=disperse --snapshot-factor=1.25 \
        --disperse-data=8 --redundancy=3

  * Create a 100GiB distributed volume which supports performance related volume options.
      $ heketi-cli volume create --size=100 --durability=none --gluster-volume-options="performance.rda-cache-limit 10MB","performance.nl-cache-positive-entry no"
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check volume size
		if size == 0 {
			return errors.New("Missing volume size")
		}


		// Create request blob
		req := &api.VolumeCreateRequest{}
		req.Size = size
		req.Durability.Type = api.DurabilityType(durability)
		req.Durability.Replicate.Replica = replica
		req.Durability.Disperse.Data = disperseData
		req.Durability.Disperse.Redundancy = redundancy
		req.Block = block

		// Check clusters
		if clusters != "" {
			req.Clusters = strings.Split(clusters, ",")
		}

		// Check volume options
		if glusterVolumeOptions != "" {
			req.GlusterVolumeOptions = strings.Split(glusterVolumeOptions, ",")
		}

		// Set group id if specified
		if gid != 0 {
			req.Gid = gid
		}

		if volname != "" {
			req.Name = volname
		}

		if snapshotFactor > 1.0 {
			req.Snapshot.Factor = float32(snapshotFactor)
			req.Snapshot.Enable = true
		}

		// Create a client
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		// Add volume
		volume, err := heketi.VolumeCreate(req)
		if err != nil {
			return err
		}


		return nil
	},
}

var volumeDeleteCommand = &cobra.Command{
	Use:     "delete",
	Short:   "Deletes the volume",
	Long:    "Deletes the volume",
	Example: "  $ heketi-cli volume delete 886a86a868711bef83001",
	RunE: func(cmd *cobra.Command, args []string) error {
		s := cmd.Flags().Args()

		//ensure proper number of args
		if len(s) < 1 {
			return errors.New("Volume id missing")
		}

		//set volumeId
		volumeId := cmd.Flags().Arg(0)

		// Create a client
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		//set url
		err = heketi.VolumeDelete(volumeId)
		if err == nil {
			fmt.Fprintf(stdout, "Volume %v deleted\n", volumeId)
		}

		return err
	},
}

var volumeExpandCommand = &cobra.Command{
	Use:   "expand",
	Short: "Expand a volume",
	Long:  "Expand a volume",
	Example: `  * Add 10GiB to a volume
    $ heketi-cli volume expand --volume=60d46d518074b13a04ce1022c8c7193c --expand-size=10
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check volume size
		if expandSize == 0 {
			return errors.New("Missing volume amount to expand")
		}

		if id == "" {
			return errors.New("Missing volume id")
		}

		// Create request
		req := &api.VolumeExpandRequest{}
		req.Size = expandSize

		// Create client
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		// Expand volume
		volume, err := heketi.VolumeExpand(id, req)
		if err != nil {
			return err
		}

		if options.Json {
			data, err := json.Marshal(volume)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, string(data))
		} else {
			printVolumeInfo(volume)
		}
		return nil
	},
}

var volumeBlockHostingRestrictionCommand = &cobra.Command{
	Use:   "set-block-hosting-restriction",
	Short: "set volume's block hosting restriction",
	Long:  "set volume's block hosting restriction",
}

var volumeBlockHostingRestrictionLockCommand = &cobra.Command{
	Use:   "locked",
	Short: "restrict creation of block volumes on block hosting volume",
	Long:  "restrict creation of block volumes on block hosting volume",
	Example: ` * Restrict creation of block volumes on the volume
    $ heketi-cli volume set-block-hosting-restriction locked 60d46d518074b13a04ce1022c8c7193c
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s := cmd.Flags().Args()

		//ensure proper number of args
		if len(s) < 1 {
			return errors.New("Volume id missing")
		}

		//set volumeId
		volumeID := cmd.Flags().Arg(0)

		// Create request
		req := &api.VolumeBlockRestrictionRequest{}
		req.Restriction = api.Locked

		// Create client
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		// Set the flag
		volume, err := heketi.VolumeSetBlockRestriction(volumeID, req)
		if err != nil {
			return err
		}

		if options.Json {
			data, err := json.Marshal(volume)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, string(data))
		} else {
			printVolumeInfo(volume)
		}
		return nil
	},
}

var volumeBlockHostingRestrictionUnlockCommand = &cobra.Command{
	Use:   "unlocked",
	Short: "allow creation of block volumes on block hosting volume",
	Long:  "allow creation of block volumes on block hosting volume",
	Example: ` * Allow creation of block volumes on the volume
    $ heketi-cli volume set-block-hosting-restriction unlocked 60d46d518074b13a04ce1022c8c7193c
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s := cmd.Flags().Args()

		//ensure proper number of args
		if len(s) < 1 {
			return errors.New("Volume id missing")
		}

		//set volumeId
		volumeID := cmd.Flags().Arg(0)

		// Create request
		req := &api.VolumeBlockRestrictionRequest{}
		req.Restriction = api.Unrestricted

		// Create client
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		// Set the flag
		volume, err := heketi.VolumeSetBlockRestriction(volumeID, req)
		if err != nil {
			return err
		}

		if options.Json {
			data, err := json.Marshal(volume)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, string(data))
		} else {
			printVolumeInfo(volume)
		}
		return nil
	},
}

var volumeInfoCommand = &cobra.Command{
	Use:     "info",
	Short:   "Retrieves information about the volume",
	Long:    "Retrieves information about the volume",
	Example: "  $ heketi-cli volume info 886a86a868711bef83001",
	RunE: func(cmd *cobra.Command, args []string) error {
		//ensure proper number of args
		s := cmd.Flags().Args()
		if len(s) < 1 {
			return errors.New("Volume id missing")
		}

		// Set volume id
		volumeId := cmd.Flags().Arg(0)

		// Create a client to talk to Heketi
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		info, err := heketi.VolumeInfo(volumeId)
		if err != nil {
			return err
		}

		if options.Json {
			data, err := json.Marshal(info)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, string(data))
		} else {
			printVolumeInfo(info)
		}
		return nil

	},
}

var volumeTemplate = `
{{- /* remove whitespace */ -}}
Name: {{.Name}}
Size: {{.Size}}
Volume Id: {{.Id}}
Cluster Id: {{.Cluster}}
Mount: {{.Mount.GlusterFS.MountPoint}}
Mount Options: {{ range $k, $v := .Mount.GlusterFS.Options }}{{$k}}={{$v}}{{ end }}
Block: {{.Block}}
Free Size: {{.BlockInfo.FreeSize}}
Reserved Size: {{.BlockInfo.ReservedSize}}
Block Hosting Restriction: {{.BlockInfo.Restriction}}
Block Volumes: {{.BlockInfo.BlockVolumes}}
Durability Type: {{.Durability.Type}}
Distribute Count: {{ . | distributeCount }}
{{- if eq .Durability.Type "replicate" }}
Replica Count: {{.Durability.Replicate.Replica}}
{{- else if eq .Durability.Type "disperse" }}
Disperse Data Count: {{.Durability.Disperse.Data}}
Disperse Redundancy Count: {{.Durability.Disperse.Redundancy}}
{{- end}}
{{- if .Snapshot.Enable }}
Snapshot Factor: {{.Snapshot.Factor | printf "%.2f"}}
{{end}}
`

func printVolumeInfo(volume *api.VolumeInfoResponse) {
	fm := template.FuncMap{
		"distributeCount": func(v *api.VolumeInfoResponse) int {
			switch v.Durability.Type {
			case api.DurabilityDistributeOnly:
				return len(v.Bricks)
			case api.DurabilityReplicate:
				return len(v.Bricks) / v.Durability.Replicate.Replica
			case api.DurabilityEC:
				return len(v.Bricks) / (v.Durability.Disperse.Data + v.Durability.Disperse.Redundancy)
			default:
				return 0
			}
		},
	}
	t, err := template.New("volume").Funcs(fm).Parse(volumeTemplate)
	if err != nil {
		panic(err)
	}
	err = t.Execute(os.Stdout, volume)
	if err != nil {
		panic(err)
	}
}

var volumeListCommand = &cobra.Command{
	Use:     "list",
	Short:   "Lists the volumes managed by Heketi",
	Long:    "Lists the volumes managed by Heketi",
	Example: "  $ heketi-cli volume list",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Create a client
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		// List volumes
		list, err := heketi.VolumeList()
		if err != nil {
			return err
		}

		if options.Json {
			data, err := json.Marshal(list)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, string(data))
		} else {
			for _, id := range list.Volumes {
				volume, err := heketi.VolumeInfo(id)
				if err != nil {
					return err
				}

				blockstr := ""
				if volume.Block {
					blockstr = " [block]"
				}
				fmt.Fprintf(stdout, "Id:%-35v Cluster:%-35v Name:%v%v\n",
					id,
					volume.Cluster,
					volume.Name,
					blockstr)
			}
		}

		return nil
	},
}

var volumeCloneCommand = &cobra.Command{
	Use:     "clone",
	Short:   "Creates a clone",
	Long:    "Creates a clone",
	Example: "  $ heketi-cli volume clone 886a86a868711bef83001",
	RunE: func(cmd *cobra.Command, args []string) error {
		//ensure proper number of args
		s := cmd.Flags().Args()
		if len(s) < 1 {
			return errors.New("Volume id missing")
		}

		// Set volume id
		volumeId := cmd.Flags().Arg(0)

		// Create request
		req := &api.VolumeCloneRequest{}
		if volname != "" {
			req.Name = volname
		}

		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		// Clone the volume
		volume, err := heketi.VolumeClone(volumeId, req)
		if err != nil {
			return err
		}

		if options.Json {
			data, err := json.Marshal(volume)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, string(data))
		} else {
			printVolumeInfo(volume)
		}
		return nil
	},
}

var volumeEndpointCommand = &cobra.Command{
	Use:   "endpoint",
	Short: "utilities for working on volume endpoint",
	Long:  "utilities for working on volume endpoint",
}

var volumeEndpointPatchCommand = &cobra.Command{
	Use:     "patch",
	Short:   "output a patch for endpoint update",
	Long:    "output a patch for endpoint update",
	Example: "  $ heketi-cli volume endpoint patch 886a86a868711bef83001",
	RunE: func(cmd *cobra.Command, args []string) error {
		s := cmd.Flags().Args()

		//ensure proper number of args
		if len(s) < 1 {
			return errors.New("Volume id missing")
		}

		//set volumeId
		volumeId := cmd.Flags().Arg(0)

		// Create a client
		heketi, err := newHeketiClient()
		if err != nil {
			return err
		}

		info, err := heketi.VolumeInfo(volumeId)
		if err != nil {
			return err
		}
		ep := createHeketiStorageEndpoints(info)
		ss, err := json.Marshal(ep.Subsets)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "{\"subsets\": %v}", string(ss))

		return err
	},
}
