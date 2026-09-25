import * as core from "@actions/core";
import type { ActionIO } from "./io.ts";

export const coreIO: ActionIO = {
  getInput: (name) => core.getInput(name),
  getIDToken: (audience) => core.getIDToken(audience),
  setSecret: (value) => {
    core.setSecret(value);
  },
  setOutput: (name, value) => {
    core.setOutput(name, value);
  },
  saveState: (name, value) => {
    core.saveState(name, value);
  },
  getState: (name) => core.getState(name),
  setFailed: (message) => {
    core.setFailed(message);
  },
  info: (message) => {
    core.info(message);
  },
  warning: (message) => {
    core.warning(message);
  },
};
