import { isDeepStrictEqual } from 'node:util';
import { z } from 'zod';

const permissionTags = new Set(['uses-permission', 'uses-permission-sdk-23', 'uses-permission-sdk-m', 'permission']);
const componentTags = new Set(['activity', 'activity-alias', 'service', 'receiver', 'provider']);
const sdkFields = ['minSdkVersion', 'targetSdkVersion', 'maxSdkVersion'];
const appFields = ['enabled', 'permission', 'debuggable', 'allowBackup', 'usesCleartextTraffic', 'networkSecurityConfig', 'extractNativeLibs'];
const componentFields = ['exported', 'enabled', 'permission', 'readPermission', 'writePermission', 'authorities', 'grantUriPermissions'];
const dataFields = ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'pathAdvancedPattern', 'pathSuffix', 'mimeType', 'mimeGroup'];
const attributes = z.record(z.string(), z.union([z.string(), z.number().int(), z.boolean()]));
const declaration = z.object({kind:z.string(), name:z.string(), attributes});
const filter = z.object({
  attributes, actions:z.array(z.string()), categories:z.array(z.string()), data:z.array(attributes),
});

export const manifestFactsSchema = z.object({
  sdk:attributes, application:attributes, permissions:z.array(declaration),
  components:z.array(declaration.extend({intent_filters:z.array(filter)})),
});

function decodeAttribute(value) {
  const quoted = /^"((?:\\.|[^"\\])*)"/.exec(value);
  if (quoted) return quoted[1].replace(/\\(["\\])/g, '$1');
  if (value === 'true' || value === 'false') return value === 'true';
  if (/^\d+$/.test(value) && Number.isSafeInteger(Number(value))) return Number(value);
  const typed = /^\(type 0x(10|11|12)\)0x([0-9a-f]{1,8})$/i.exec(value);
  if (!typed) return value;
  const number = Number.parseInt(typed[2], 16);
  if (typed[1] === '12') return number !== 0;
  return typed[1] === '10' ? number | 0 : number;
}

function readTree(output) {
  const roots = [], stack = [];
  for (const line of output.split(/\r?\n/)) {
    const element = /^(\s*)E: ([^\s]+)(?:\s|$)/.exec(line);
    if (element) {
      const indent = element[1].length;
      while (stack.length && stack.at(-1).indent >= indent) stack.pop();
      const node = {indent, tag:element[2], attributes:new Map(), children:[]};
      (stack.at(-1)?.children ?? roots).push(node);
      stack.push(node);
      continue;
    }
    const attr = /^(\s*)A: (?:android|http:\/\/schemas\.android\.com\/apk\/res\/android):(\w+)(?:\([^)]*\))?=(.*)$/.exec(line);
    if (attr && stack.length && attr[1].length > stack.at(-1).indent) {
      stack.at(-1).attributes.set(attr[2], decodeAttribute(attr[3].trimEnd()));
    }
  }
  return roots.length === 1 && roots[0].tag === 'manifest' ? roots[0] : null;
}

function select(node, keys) {
  return Object.fromEntries(keys.filter(key=>node?.attributes.has(key)).map(key=>[key,node.attributes.get(key)]));
}

function sorted(items) {
  return items.map(item=>[JSON.stringify(item),item])
    .sort(([left],[right])=>left < right ? -1 : left > right ? 1 : 0)
    .map(([, item])=>item);
}

function className(name, pkg) {
  if (name.startsWith('.')) return pkg + name;
  if (!name.includes('.') && /^[\w$]+$/.test(name)) return pkg + '.' + name;
  return name;
}

function describeFilter(node) {
  const names = tag => node.children.filter(child=>child.tag === tag)
    .map(child=>child.attributes.get('name')).filter(name=>typeof name === 'string').sort();
  return {
    attributes:select(node,['autoVerify', 'priority', 'order']),
    actions:names('action'), categories:names('category'),
    data:sorted(node.children.filter(child=>child.tag === 'data').map(child=>select(child,dataFields))),
  };
}

export function parseManifestFacts(output, pkg) {
  const root = readTree(output);
  if (!root) return null;
  const app = root.children.find(child=>child.tag === 'application');
  const permissions = [], components = [];
  for (const node of root.children) {
    const name = node.attributes.get('name');
    if (!permissionTags.has(node.tag) || typeof name !== 'string') continue;
    permissions.push({kind:node.tag, name, attributes:select(node,['maxSdkVersion', 'usesPermissionFlags', 'protectionLevel'])});
  }
  for (const node of app?.children ?? []) {
    const name = node.attributes.get('name');
    if (!componentTags.has(node.tag) || typeof name !== 'string') continue;
    const fields = select(node,componentFields);
    const target = node.attributes.get('targetActivity');
    if (typeof target === 'string') fields.targetActivity = className(target,pkg);
    const intent_filters = sorted(node.children.filter(child=>child.tag === 'intent-filter').map(describeFilter));
    components.push({kind:node.tag, name:className(name,pkg), attributes:fields, intent_filters});
  }
  return {
    sdk:select(root.children.find(child=>child.tag === 'uses-sdk'),sdkFields),
    application:select(app,appFields), permissions:sorted(permissions), components:sorted(components),
  };
}

const emptyManifest = {sdk:{}, application:{}, permissions:[], components:[]};

function compareDeclarations(before, after) {
  const group = items => {
    const groups = new Map();
    for (const item of items) {
      const key = JSON.stringify([item.kind,item.name]);
      if (!groups.has(key)) groups.set(key,[]);
      groups.get(key).push(item);
    }
    return groups;
  };
  const first = group(before), second = group(after);
  const changes = [];
  for (const key of new Set([...first.keys(),...second.keys()])) {
    const left = first.get(key) ?? [], right = second.get(key) ?? [];
    if (isDeepStrictEqual(left,right)) continue;
    const {kind,name} = (right[0] ?? left[0]);
    changes.push({kind, name, change:!left.length ? 'added' : !right.length ? 'removed' : 'changed', before:left, after:right});
  }
  return changes;
}

export function compareManifestFacts(left, right) {
  const before = left ? left.manifest_facts : emptyManifest;
  const after = right ? right.manifest_facts : emptyManifest;
  if (!before || !after) return {status:'insufficient_inventory'};
  const change = key => isDeepStrictEqual(before[key],after[key]) ? null : {before:before[key],after:after[key]};
  const sdk = change('sdk'), application = change('application');
  const permissions = compareDeclarations(before.permissions,after.permissions);
  const components = compareDeclarations(before.components,after.components);
  return {status:sdk || application || permissions.length || components.length ? 'changed' : 'unchanged',
    sdk, application, permissions, components};
}
