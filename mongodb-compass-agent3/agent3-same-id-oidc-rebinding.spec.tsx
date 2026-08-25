import { expect } from 'chai';
import React from 'react';
import {
  render,
  waitFor,
} from '@mongodb-js/testing-library-compass';
import {
  InMemoryConnectionStorage,
  type ImportConnectionOptions,
} from '@mongodb-js/connection-storage/provider';
import type { ConnectionInfo } from '@mongodb-js/connection-info';
import {
  deserializeConnections,
  serializeConnections,
} from '../../../connection-storage/src/import-export-connection';
import { getDataServiceForConnection } from './connections-store-redux';

const SAME_ID = '11111111-1111-4111-8111-111111111111';
const FRESH_ID = '22222222-2222-4222-8222-222222222222';
const SERIALIZED_STATE_MARKER = 'AGENT3_FAKE_OIDC_SERIALIZED_STATE';

function connection(
  id: string,
  host: string,
  name: string
): ConnectionInfo {
  return {
    id,
    favorite: { name },
    savedConnectionType: 'favorite',
    connectionOptions: {
      connectionString: `mongodb://${host}/?authMechanism=MONGODB-OIDC`,
      oidc: {
        enableUntrustedEndpoints: true,
      },
    },
  };
}

describe('Agent 3 same-ID imported OIDC state rebinding', function () {
  it('reapplies live OIDC serializedState to a same-ID replacement but not a fresh-ID control', async function () {
    const original = connection(SAME_ID, 'original.example', 'Original OIDC');
    const replacement = connection(
      SAME_ID,
      'replacement.example',
      'Imported Replacement'
    );
    const freshControl = connection(
      FRESH_ID,
      'control.example',
      'Fresh ID Control'
    );

    const connectionStorage = new InMemoryConnectionStorage([original]);

    connectionStorage.deserializeConnections = async ({
      content,
      options = {},
    }: {
      content: string;
      options?: ImportConnectionOptions;
    }) => {
      return deserializeConnections(content, options);
    };

    connectionStorage.importConnections = async ({
      content,
      options = {},
    }: {
      content: string;
      options?: ImportConnectionOptions;
    }) => {
      const imported = await deserializeConnections(content, options);
      await Promise.all(
        imported.map((connectionInfo) =>
          connectionStorage.save({ connectionInfo })
        )
      );
    };

    const observedConnectOptions: Array<{
      connectionString: string;
      serializedState?: string;
    }> = [];

    const { connectionsStore } = render(<div />, {
      connections: [original],
      connectionStorage,
      preferences: { persistOIDCTokens: false },
      connectFn: async (connectionOptions) => {
        observedConnectOptions.push({
          connectionString: connectionOptions.connectionString,
          serializedState: connectionOptions.oidc?.serializedState,
        });
        return {};
      },
    });

    // Establish a legitimate OIDC connection and let the production store
    // receive updated plugin state exactly through connectionInfoSecretsChanged.
    await connectionsStore.actions.connect(original);
    const originalDataService = getDataServiceForConnection(SAME_ID);
    let updatedSecretReads = 0;
    originalDataService.getUpdatedSecrets = async () => {
      updatedSecretReads += 1;
      return {
        oidc: {
          serializedState: SERIALIZED_STATE_MARKER,
        },
      };
    };
    originalDataService.emit('connectionInfoSecretsChanged');

    await waitFor(() => {
      expect(updatedSecretReads).to.equal(1);
    });
    // Allow the Promise continuation that writes SecretsForConnection to run.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

    connectionsStore.actions.disconnect(SAME_ID);

    // Import a legitimate Compass connection artifact that preserves the UUID
    // but changes the MongoDB endpoint and does not contain serializedState.
    const replacementArtifact = await serializeConnections([replacement], {
      removeSecrets: true,
    });
    await connectionsStore.actions.importConnections({
      content: replacementArtifact,
    });

    const importedReplacement =
      connectionsStore.getState().connections.byId[SAME_ID].info;
    expect(importedReplacement.connectionOptions.connectionString).to.equal(
      replacement.connectionOptions.connectionString
    );
    expect(importedReplacement.connectionOptions.oidc?.serializedState).to.be
      .undefined;

    await connectionsStore.actions.connect(importedReplacement);

    const sameIdAttempt = observedConnectOptions[1];
    expect(sameIdAttempt.connectionString).to.equal(
      replacement.connectionOptions.connectionString
    );
    expect(sameIdAttempt.serializedState).to.equal(SERIALIZED_STATE_MARKER);

    connectionsStore.actions.disconnect(SAME_ID);

    // Negative control: the identical replacement with a newly generated UUID
    // must not receive state belonging to SAME_ID.
    const controlArtifact = await serializeConnections([freshControl], {
      removeSecrets: true,
    });
    await connectionsStore.actions.importConnections({ content: controlArtifact });

    const importedControl =
      connectionsStore.getState().connections.byId[FRESH_ID].info;
    await connectionsStore.actions.connect(importedControl);

    const freshIdAttempt = observedConnectOptions[2];
    expect(freshIdAttempt.connectionString).to.equal(
      freshControl.connectionOptions.connectionString
    );
    expect(freshIdAttempt.serializedState).to.be.undefined;

    console.log(
      'AGENT3_STORE_RESULT=' +
        JSON.stringify({
          compassVersion: '1.49.14',
          sameIdReplacementEndpoint:
            sameIdAttempt.connectionString ===
            replacement.connectionOptions.connectionString,
          sameIdReceivedOriginalState:
            sameIdAttempt.serializedState === SERIALIZED_STATE_MARKER,
          freshIdReceivedOriginalState:
            freshIdAttempt.serializedState === SERIALIZED_STATE_MARKER,
          negativeControlPassed: freshIdAttempt.serializedState === undefined,
        })
    );
  });
});
