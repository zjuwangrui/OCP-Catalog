import { coreArtifacts } from './core';
import { cryptoArtifacts } from './crypto';
import { examplesArtifacts } from './examples';
import { handshakeArtifacts } from './handshake';
import { registrationArtifacts } from './registration';
import type { PageArtifactDefinition } from './types';

export const artifactRegistry: Record<string, PageArtifactDefinition> = {
  ...coreArtifacts,
  ...cryptoArtifacts,
  ...handshakeArtifacts,
  ...registrationArtifacts,
  ...examplesArtifacts,
};
