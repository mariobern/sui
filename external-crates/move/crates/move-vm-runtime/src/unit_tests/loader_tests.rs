// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

// Simplifies logic around re-using ModuleIds.
#![allow(clippy::redundant_clone)]

use crate::{
    dev_utils::{
        compilation_utils::{compile_modules_in_file, expect_modules},
        in_memory_test_adapter::InMemoryTestAdapter,
        storage::InMemoryStorage,
        vm_test_adapter::VMTestAdapter,
    },
    jit::execution::ast::{DepthFormula, IntraPackageKey, Type, VTableKey},
    natives::functions::NativeFunctions,
    runtime::MoveRuntime,
    shared::{
        gas::UnmeteredGasMeter,
        linkage_context::LinkageContext,
        serialization::SerializedReturnValues,
        types::{PackageStorageId, RuntimePackageId},
    },
    string_interner,
};
use move_binary_format::{
    file_format::{
        empty_module, AddressIdentifierIndex, IdentifierIndex, ModuleHandle, TableIndex,
    },
    CompiledModule,
};
use move_compiler::Compiler;
use move_core_types::{
    account_address::AccountAddress,
    ident_str,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, TypeTag},
    runtime_value::MoveValue,
};
use move_vm_config::{runtime::VMConfig, verifier::VerifierConfig};
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    thread,
};

const ADDR2: AccountAddress = {
    let mut address = [0u8; AccountAddress::LENGTH];
    address[AccountAddress::LENGTH - 1] = 2u8;
    AccountAddress::new(address)
};
const ADDR3: AccountAddress = {
    let mut address = [0u8; AccountAddress::LENGTH];
    address[AccountAddress::LENGTH - 1] = 3u8;
    AccountAddress::new(address)
};
const ADDR4: AccountAddress = {
    let mut address = [0u8; AccountAddress::LENGTH];
    address[AccountAddress::LENGTH - 1] = 4u8;
    AccountAddress::new(address)
};
const ADDR5: AccountAddress = {
    let mut address = [0u8; AccountAddress::LENGTH];
    address[AccountAddress::LENGTH - 1] = 5u8;
    AccountAddress::new(address)
};
const ADDR6: AccountAddress = {
    let mut address = [0u8; AccountAddress::LENGTH];
    address[AccountAddress::LENGTH - 1] = 6u8;
    AccountAddress::new(address)
};

struct Adapter {
    vm: Arc<RwLock<InMemoryTestAdapter>>,
    store: RelinkingStore,
    functions: Vec<(ModuleId, Identifier)>,
}

#[derive(Clone)]
struct RelinkingStore {
    linkage: LinkageContext,
    // TODO: when we add type origin to `LinkageContext`, we should remove this field
    #[allow(dead_code)]
    type_origin: HashMap<(ModuleId, Identifier), ModuleId>,
}

impl Adapter {
    fn new(store: InMemoryStorage) -> Self {
        let functions = vec![
            (
                ModuleId::new(ADDR2, Identifier::new("A").unwrap()),
                Identifier::new("entry_a").unwrap(),
            ),
            (
                ModuleId::new(ADDR2, Identifier::new("D").unwrap()),
                Identifier::new("entry_d").unwrap(),
            ),
            (
                ModuleId::new(ADDR2, Identifier::new("E").unwrap()),
                Identifier::new("entry_e").unwrap(),
            ),
            (
                ModuleId::new(ADDR2, Identifier::new("F").unwrap()),
                Identifier::new("entry_f").unwrap(),
            ),
            (
                ModuleId::new(ADDR2, Identifier::new("C").unwrap()),
                Identifier::new("just_c").unwrap(),
            ),
        ];
        let config = VMConfig {
            verifier: VerifierConfig {
                max_dependency_depth: Some(100),
                ..Default::default()
            },
            ..Default::default()
        };
        let runtime = MoveRuntime::new(NativeFunctions::empty_for_testing().unwrap(), config);
        let vm = Arc::new(RwLock::new(
            InMemoryTestAdapter::new_with_runtime_and_storage(runtime, store),
        ));
        let linkage = LinkageContext::new(ADDR2, HashMap::new());
        Self {
            store: RelinkingStore::create_linkage(linkage, HashMap::new()),
            vm,
            functions,
        }
    }

    fn linkage(
        &self,
        context: PackageStorageId,
        linkage: HashMap<RuntimePackageId, PackageStorageId>,
        type_origin: HashMap<(ModuleId, Identifier), ModuleId>,
    ) -> Self {
        Self {
            store: RelinkingStore::create_linkage(
                LinkageContext {
                    root_package: context,
                    linkage_table: linkage,
                },
                type_origin,
            ),
            vm: self.vm.clone(),
            functions: self.functions.clone(),
        }
    }

    fn publish_modules(&mut self, modules: Vec<CompiledModule>) {
        let account_id = {
            let addrs = BTreeSet::from_iter(modules.iter().map(|m| *m.self_id().address()));
            assert!(addrs.len() == 1);
            *addrs.first().unwrap()
        };
        self.vm
            .write()
            .publish_package_modules_for_test(self.store.linkage.clone(), account_id, modules)
            .unwrap_or_else(|e| panic!("failure publishing modules: {e:?}"));
    }

    fn publish_modules_with_error(&mut self, modules: Vec<CompiledModule>) {
        self.vm
            .write()
            .publish_package_modules_for_test(self.store.linkage.clone(), ADDR2, modules)
            .expect_err("publishing must fail");
    }

    fn publish_module_bundle(&mut self, modules: Vec<CompiledModule>) {
        self.vm
            .write()
            .publish_package_modules_for_test(self.store.linkage.clone(), ADDR2, modules)
            .unwrap_or_else(|e| panic!("failure publishing modules: {e:?}"));
    }

    fn load_type(&self, type_tag: &TypeTag) -> Type {
        let vm = self.vm.write();
        let session = vm.make_vm(self.store.linkage.clone()).unwrap();
        session
            .load_type(type_tag)
            .expect("Loading type should succeed")
    }

    fn compute_depth_of_datatype(
        &self,
        module_id: &ModuleId,
        struct_name: &IdentStr,
    ) -> DepthFormula {
        let vm = self.vm.write();
        let session = vm.make_vm(self.store.linkage.clone()).unwrap();
        session
            .virtual_tables
            .calculate_depth_of_type(&VTableKey {
                package_key: *module_id.address(),
                inner_pkg_key: IntraPackageKey {
                    module_name: string_interner()
                        .get_or_intern_ident_str(module_id.name())
                        .unwrap(),
                    member_name: string_interner()
                        .get_or_intern_ident_str(struct_name)
                        .unwrap(),
                },
            })
            .expect("computing depth of datatype should succeed")
    }

    fn get_type_tag(&self, ty: &Type) -> TypeTag {
        let vm = self.vm.write();
        let session = vm.make_vm(self.store.linkage.clone()).unwrap();
        session
            .virtual_tables
            .type_to_type_tag(ty)
            .expect("Converting to type tag should succeed")
    }

    fn call_functions(&self) {
        for (module_id, name) in &self.functions {
            self.call_function(module_id, name);
        }
    }

    fn call_functions_async(&self, reps: usize) {
        let mut children = vec![];
        for _ in 0..reps {
            for (module_id, name) in self.functions.clone() {
                let vm = self.vm.clone();
                let data_store = self.store.clone();
                children.push(thread::spawn(move || {
                    let bind = vm.write();
                    let mut session = bind.make_vm(data_store.linkage.clone()).unwrap();
                    session
                        .execute_function_bypass_visibility(
                            &module_id,
                            &name,
                            vec![],
                            Vec::<Vec<u8>>::new(),
                            &mut UnmeteredGasMeter,
                        )
                        .unwrap_or_else(|_| {
                            panic!("Failure executing {:?}::{:?}", module_id, name)
                        });
                }));
            }
        }
        for child in children {
            let _ = child.join();
        }
    }

    fn call_function_with_return(&self, module: &ModuleId, name: &IdentStr) -> Vec<MoveValue> {
        self.call_function(module, name)
            .return_values
            .into_iter()
            .map(|(bytes, ty)| {
                MoveValue::simple_deserialize(&bytes[..], &ty)
                    .expect("Can't deserialize return value")
            })
            .collect()
    }

    fn validate_linkage_with_err(&self) {
        let vm = self.vm.write();
        let Err(_) = vm.make_vm(self.store.linkage.clone()) else {
            panic!("Should fail to make VM since function is missing");
        };
    }

    fn call_function(&self, module: &ModuleId, name: &IdentStr) -> SerializedReturnValues {
        let vm = self.vm.write();
        let mut session = vm.make_vm(self.store.linkage.clone()).unwrap();
        session
            .execute_function_bypass_visibility(
                module,
                name,
                vec![],
                Vec::<Vec<u8>>::new(),
                &mut UnmeteredGasMeter,
            )
            .unwrap_or_else(|e| panic!("Failure executing {module:?}::{name:?}: {e:#?}"))
    }
}

impl RelinkingStore {
    fn create_linkage(
        linkage: LinkageContext,
        type_origin: HashMap<(ModuleId, Identifier), ModuleId>,
    ) -> Self {
        Self {
            linkage,
            type_origin,
        }
    }
}

fn get_fixture(fixture: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.extend(["src", "unit_tests", "move_packages", fixture]);
    path.to_string_lossy().into_owned()
}

fn get_loader_tests_modules() -> Vec<CompiledModule> {
    compile_modules_in_file(&get_fixture("loader_tests_modules.move"), &[])
}

fn get_depth_tests_modules() -> Vec<CompiledModule> {
    compile_modules_in_file(&get_fixture("depth_tests_modules.move"), &[])
}

fn get_relinker_tests_modules_with_deps<'s>(
    root_account_addr: RuntimePackageId,
    module: &'s str,
    deps: impl IntoIterator<Item = &'s str>,
) -> anyhow::Result<Vec<CompiledModule>> {
    fn fixture_string_path(module: &str) -> String {
        get_fixture(&format!("rt_{module}.move"))
    }

    let (_, units) = Compiler::from_files(
        None,
        vec![fixture_string_path(module)],
        deps.into_iter().map(fixture_string_path).collect(),
        BTreeMap::<String, _>::new(),
    )
    .build_and_report()?;

    Ok(expect_modules(units)
        .filter(|m| *m.self_id().address() == root_account_addr)
        .collect())
}

#[test]
fn load() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());
    let modules = get_loader_tests_modules();
    adapter.publish_modules(modules);
    // calls all functions sequentially
    adapter.call_functions();
}

#[test]
fn test_depth() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());
    let modules = get_depth_tests_modules();
    let structs = vec![
        (
            "A",
            "Box",
            DepthFormula {
                terms: vec![(0, 1)],
                constant: None,
            },
        ),
        (
            "A",
            "Box3",
            DepthFormula {
                terms: vec![(0, 3)],
                constant: None,
            },
        ),
        (
            "A",
            "Box7",
            DepthFormula {
                terms: vec![(0, 7)],
                constant: None,
            },
        ),
        (
            "A",
            "Box15",
            DepthFormula {
                terms: vec![(0, 15)],
                constant: None,
            },
        ),
        (
            "A",
            "Box31",
            DepthFormula {
                terms: vec![(0, 31)],
                constant: None,
            },
        ),
        (
            "A",
            "Box63",
            DepthFormula {
                terms: vec![(0, 63)],
                constant: None,
            },
        ),
        (
            "A",
            "Box127",
            DepthFormula {
                terms: vec![(0, 127)],
                constant: None,
            },
        ),
        (
            "A",
            "S",
            DepthFormula {
                terms: vec![],
                constant: Some(3),
            },
        ),
        (
            "B",
            "S",
            DepthFormula {
                terms: vec![],
                constant: Some(2),
            },
        ),
        (
            "C",
            "S",
            DepthFormula {
                terms: vec![],
                constant: Some(2),
            },
        ),
        (
            "D",
            "S",
            DepthFormula {
                terms: vec![],
                constant: Some(3),
            },
        ),
        (
            "E",
            "S",
            DepthFormula {
                terms: vec![(0, 2)],
                constant: Some(3),
            },
        ),
        (
            "F",
            "S",
            DepthFormula {
                terms: vec![(0, 1)],
                constant: Some(2),
            },
        ),
        (
            "G",
            "S",
            DepthFormula {
                terms: vec![(0, 5), (1, 3)],
                constant: Some(6),
            },
        ),
        (
            "H",
            "S",
            DepthFormula {
                terms: vec![(0, 2), (1, 4)],
                constant: Some(5),
            },
        ),
        (
            "I",
            "L",
            DepthFormula {
                terms: vec![(0, 2)],
                constant: Some(4),
            },
        ),
        (
            "I",
            "G",
            DepthFormula {
                terms: vec![],
                constant: Some(3),
            },
        ),
        (
            "I",
            "H",
            DepthFormula {
                terms: vec![(0, 1)],
                constant: Some(2),
            },
        ),
        (
            "I",
            "E",
            DepthFormula {
                terms: vec![(0, 2)],
                constant: Some(3),
            },
        ),
        (
            "I",
            "F",
            DepthFormula {
                terms: vec![(0, 1)],
                constant: Some(2),
            },
        ),
        (
            "I",
            "S",
            DepthFormula {
                terms: vec![(0, 2), (1, 7)],
                constant: Some(9),
            },
        ),
        (
            "I",
            "LL",
            DepthFormula {
                terms: vec![(1, 2)],
                constant: Some(4),
            },
        ),
        (
            "I",
            "N",
            DepthFormula {
                terms: vec![],
                constant: Some(2),
            },
        ),
    ];
    adapter.publish_modules(modules);
    // loads all structs sequentially
    for (module_name, type_name, expected_depth) in structs.iter() {
        let computed_depth = &adapter.compute_depth_of_datatype(
            &ModuleId::new(ADDR2, Identifier::new(module_name.to_string()).unwrap()),
            ident_str!(type_name),
        );
        assert_eq!(computed_depth, expected_depth);
    }
}

#[test]
fn load_concurrent() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());
    let modules = get_loader_tests_modules();
    adapter.publish_modules(modules);
    // makes 15 threads
    adapter.call_functions_async(3);
}

#[test]
fn load_concurrent_many() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());
    let modules = get_loader_tests_modules();
    adapter.publish_modules(modules);
    // makes 150 threads
    adapter.call_functions_async(30);
}

#[test]
fn relink() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let a0 = ModuleId::new(ADDR4, ident_str!("a").to_owned());
    let b0 = ModuleId::new(ADDR3, ident_str!("b").to_owned());
    let c0 = ModuleId::new(ADDR2, ident_str!("c").to_owned());
    let c1 = ModuleId::new(ADDR5, ident_str!("c").to_owned());

    let c0_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v0", []).unwrap();
    let c1_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v1", []).unwrap();
    let b0_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v0", ["c_v0"]).unwrap();
    let a0_modules = get_relinker_tests_modules_with_deps(ADDR4, "a_v0", ["b_v0", "c_v1"]).unwrap();

    // Publish the first version of C, and B which is published depending on it.
    adapter.publish_modules(c0_modules);
    adapter
        .linkage(
            ADDR3,
            HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
            HashMap::new(),
        )
        .publish_modules(b0_modules);

    assert_eq!(
        vec![MoveValue::U64(42 + 1)],
        adapter
            .linkage(
                ADDR3,
                HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3),]),
                HashMap::new(),
            )
            .call_function_with_return(&b0, ident_str!("b")),
    );

    let mut adapter = adapter.linkage(
        ADDR5,
        /* linkage */ HashMap::from_iter([(ADDR2, ADDR5)]),
        /* type origin */
        HashMap::from_iter([
            ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
            ((c1.clone(), ident_str!("R").to_owned()), c1.clone()),
        ]),
    );

    // Publish the next version of C, and then A which depends on the new version of C, but also B.
    // B will be relinked to use C when executed in the adapter relinking against A.
    adapter.publish_modules(c1_modules);
    let mut adapter = adapter.linkage(
        ADDR4,
        HashMap::from([(ADDR2, ADDR5), (ADDR3, ADDR3), (ADDR4, ADDR4)]),
        HashMap::new(),
    );
    adapter.publish_modules(a0_modules);

    assert_eq!(
        vec![MoveValue::U64(44 + 43 + 1)],
        adapter.call_function_with_return(&a0, ident_str!("a")),
    );
}

#[test]
fn relink_publish_err() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let c0_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v0", []).unwrap();
    let b1_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v1", ["c_v1"]).unwrap();

    // B was built against the later version of C but published against the earlier version,
    // which should fail because a function is missing.
    adapter.publish_modules(c0_modules);
    adapter
        .linkage(
            ADDR3,
            HashMap::from_iter([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
            HashMap::from_iter([]),
        )
        .publish_modules_with_error(b1_modules);
}

#[test]
fn relink_load_err() {
    let data_store = InMemoryStorage::new();
    let adapter = Adapter::new(data_store);

    let b0 = ModuleId::new(ADDR3, ident_str!("b").to_owned());
    let b1 = ModuleId::new(ADDR6, ident_str!("b").to_owned());
    let c0 = ModuleId::new(ADDR2, ident_str!("c").to_owned());
    let c1 = ModuleId::new(ADDR5, ident_str!("c").to_owned());

    let c0_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v0", []).unwrap();
    let c1_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v1", []).unwrap();
    let b0_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v0", ["c_v0"]).unwrap();
    let b1_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v1", ["c_v1"]).unwrap();

    // B v0 works with C v0
    adapter
        .linkage(
            *c0.address(),
            HashMap::from([(*c0.address(), *c0.address())]),
            HashMap::new(),
        )
        .publish_modules(c0_modules);
    let mut adapter = adapter.linkage(
        *b0.address(),
        HashMap::from([
            (*c0.address(), *c0.address()),
            (*b0.address(), *b0.address()),
        ]),
        HashMap::new(),
    );
    adapter.publish_modules(b0_modules);

    assert_eq!(
        vec![MoveValue::U64(42 + 1)],
        adapter.call_function_with_return(&b0, ident_str!("b")),
    );

    adapter
        .linkage(
            *c1.address(),
            /* linkage */
            HashMap::from_iter([(*c0.address(), *c1.address())]),
            /* type origin */
            HashMap::from_iter([
                ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
                ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
            ]),
        )
        .publish_modules(c1_modules);

    // B v1 works with C v1
    let mut adapter = adapter.linkage(
        *b1.address(),
        /* linkage */
        HashMap::from_iter([
            (*b0.address(), *b1.address()),
            (*c0.address(), *c1.address()),
        ]),
        /* type origin */
        HashMap::from_iter([
            ((b0.clone(), ident_str!("S").to_owned()), b1.clone()),
            ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
            ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
        ]),
    );
    adapter.publish_modules(b1_modules);

    assert_eq!(
        vec![MoveValue::U64(44 * 43)],
        adapter.call_function_with_return(&b0, ident_str!("b")),
    );

    // But B v1 *does not* work with C v0
    adapter
        .linkage(
            *b1.address(),
            /* linkage */
            HashMap::from_iter([
                (*b0.address(), *b1.address()),
                (*c0.address(), *c0.address()),
            ]),
            /* type origin */
            HashMap::from_iter([
                ((b0.clone(), ident_str!("S").to_owned()), b1.clone()),
                ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
                ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
            ]),
        )
        .validate_linkage_with_err();
}

#[test]
fn relink_type_identity() {
    let data_store = InMemoryStorage::new();
    let adapter = Adapter::new(data_store);

    let b0 = ModuleId::new(ADDR3, ident_str!("b").to_owned());
    let c0 = ModuleId::new(ADDR2, ident_str!("c").to_owned());
    let b1 = ModuleId::new(ADDR6, ident_str!("b").to_owned());
    let c1 = ModuleId::new(ADDR5, ident_str!("c").to_owned());
    let c0_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v0", []).unwrap();
    let c1_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v1", []).unwrap();
    let b1_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v1", ["c_v1"]).unwrap();

    let mut adapter = adapter.linkage(
        *c0.address(),
        HashMap::from([(*c0.address(), *c0.address())]),
        HashMap::new(),
    );
    adapter.publish_modules(c0_modules);
    let c0_s = adapter.load_type(&TypeTag::from_str("0x2::c::S").unwrap());

    adapter
        .linkage(
            *c1.address(),
            /* linkage */
            HashMap::from_iter([(*c0.address(), *c1.address())]),
            /* type origin */
            HashMap::from_iter([
                ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
                ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
            ]),
        )
        .publish_modules(c1_modules);

    let mut adapter = adapter.linkage(
        *b1.address(),
        /* linkage */
        HashMap::from_iter([
            (*b0.address(), *b1.address()),
            (*c0.address(), *c1.address()),
        ]),
        /* type origin */
        HashMap::from_iter([
            ((b0.clone(), ident_str!("S").to_owned()), b1.clone()),
            ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
            ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
        ]),
    );
    adapter.publish_modules(b1_modules);

    let c1_s = adapter.load_type(&TypeTag::from_str("0x2::c::S").unwrap());
    let b1_s = adapter.load_type(&TypeTag::from_str("0x3::b::S").unwrap());

    assert_eq!(c0_s, c1_s);
    assert_ne!(c1_s, b1_s);
}

/// XXX/TODO(vm-rework): need to fix defining IDs for types for this test to pass
#[test]
fn relink_defining_module_successive() {
    let c0 = ModuleId::new(ADDR2, ident_str!("c").to_owned());
    let c1 = ModuleId::new(ADDR5, ident_str!("c").to_owned());
    let c2 = ModuleId::new(ADDR6, ident_str!("c").to_owned());
    // This test simulates building up a sequence of upgraded packages over a number of publishes
    let data_store = InMemoryStorage::new();
    let mut adapter = Adapter::new(data_store).linkage(
        *c0.address(),
        HashMap::from([(ADDR2, ADDR2)]),
        HashMap::from([((c0.clone(), ident_str!("S").to_owned()), c0.clone())]),
    );

    let c0_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v0", []).unwrap();
    let c1_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v1", []).unwrap();
    let c2_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v2", []).unwrap();

    adapter.publish_modules(c0_modules);
    let c0_s = adapter.load_type(&TypeTag::from_str("0x2::c::S").unwrap());

    let mut adapter = adapter.linkage(
        *c1.address(),
        /* linkage */ HashMap::from_iter([(*c0.address(), *c1.address())]),
        /* type origin */
        HashMap::from_iter([
            ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
            ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
        ]),
    );

    adapter.publish_modules(c1_modules);
    let c1_s = adapter.load_type(&TypeTag::from_str("0x2::c::S").unwrap());
    let c1_r = adapter.load_type(&TypeTag::from_str("0x2::c::R").unwrap());

    let mut adapter = adapter.linkage(
        *c2.address(),
        /* linkage */ HashMap::from_iter([(*c0.address(), *c2.address())]),
        /* type origin */
        HashMap::from_iter([
            ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
            ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
            ((c0.clone(), ident_str!("Q").to_owned()), c2.clone()),
        ]),
    );

    adapter.publish_modules(c2_modules);
    let c2_s = adapter.load_type(&TypeTag::from_str("0x2::c::S").unwrap());
    let c2_r = adapter.load_type(&TypeTag::from_str("0x2::c::R").unwrap());
    let c2_q = adapter.load_type(&TypeTag::from_str("0x2::c::Q").unwrap());

    for s in &[c0_s, c1_s, c2_s] {
        let TypeTag::Struct(st) = adapter.get_type_tag(s) else {
            panic!("Not a struct: {s:?}")
        };

        assert_eq!(st.module_id(), c0);
    }

    for r in &[c1_r, c2_r] {
        let TypeTag::Struct(st) = adapter.get_type_tag(r) else {
            panic!("Not a struct: {r:?}")
        };

        assert_eq!(st.module_id(), c1);
    }

    let TypeTag::Struct(st) = adapter.get_type_tag(&c2_q) else {
        panic!("Not a struct: {c2_q:?}")
    };

    assert_eq!(st.module_id(), c2);
}

/// XXX/TODO(vm-rework): need to fix defining IDs for types for this test to pass
#[test]
fn relink_defining_module_oneshot() {
    // Simulates the loader being made aware of the final package in a sequence of upgrades (perhaps
    // a previous instance of the VM and loader participated in the publishing of previous versions)
    // but still needing to correctly set-up the defining modules for the types in the latest
    // version of the package, based on the linkage table at the time of loading/publishing:

    let data_store = InMemoryStorage::new();

    let c0 = ModuleId::new(ADDR2, ident_str!("c").to_owned());
    let c1 = ModuleId::new(ADDR5, ident_str!("c").to_owned());
    let c2 = ModuleId::new(ADDR6, ident_str!("c").to_owned());

    let c2_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v2", []).unwrap();

    let mut adapter = Adapter::new(data_store).linkage(
        *c2.address(),
        /* linkage */ HashMap::from_iter([(*c0.address(), *c2.address())]),
        /* type origin */
        HashMap::from_iter([
            ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
            ((c0.clone(), ident_str!("R").to_owned()), c1.clone()),
            ((c0.clone(), ident_str!("Q").to_owned()), c2.clone()),
        ]),
    );

    adapter.publish_modules(c2_modules);
    let s = adapter.load_type(&TypeTag::from_str("0x2::c::S").unwrap());
    let r = adapter.load_type(&TypeTag::from_str("0x2::c::R").unwrap());
    let q = adapter.load_type(&TypeTag::from_str("0x2::c::Q").unwrap());

    let TypeTag::Struct(s) = adapter.get_type_tag(&s) else {
        panic!("Not a struct: {s:?}")
    };

    let TypeTag::Struct(r) = adapter.get_type_tag(&r) else {
        panic!("Not a struct: {r:?}")
    };

    let TypeTag::Struct(q) = adapter.get_type_tag(&q) else {
        panic!("Not a struct: {q:?}")
    };

    assert_eq!(s.module_id(), c0);
    assert_eq!(r.module_id(), c1);
    assert_eq!(q.module_id(), c2);
}

// TODO(vm-rewrite): Update and re-enable this test once we add failpoints to the VM
// #[test]
// fn relink_defining_module_cleanup() {
//     // If loading fails for a module that pulls in a module that was defined at an earlier version
//     // of the package, roll-back should occur cleanly.
//     let data_store = InMemoryStorage::new();
//
//     let c0 = ModuleId::new(ADDR2, ident_str!("c").to_owned());
//     let b0 = ModuleId::new(ADDR3, ident_str!("b").to_owned());
//     let b1 = ModuleId::new(ADDR6, ident_str!("b").to_owned());
//
//     let adapter = Adapter::new(data_store);
//     let c0_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v0", []).unwrap();
//     let b1_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v1", ["c_v1"]).unwrap();
//
//     // B was built against the later version of C but published against the earlier version,
//     // which should fail because a function is missing.
//     adapter
//         .linkage(
//             *c0.address(),
//             /* linkage */
//             HashMap::from_iter([(*c0.address(), *c0.address())]),
//             /* type origin */
//             HashMap::from_iter([((c0.clone(), ident_str!("S").to_owned()), c0.clone())]),
//         )
//         .publish_modules(c0_modules);
//
//     // Somehow dependency verification fails, and the publish succeeds.
//     fail::cfg("verifier-failpoint-4", "100%return").unwrap();
//     let mut adapter = adapter.linkage(
//         *b0.address(),
//         /* linkage */
//         HashMap::from_iter([
//             (*b0.address(), *b1.address()),
//             (*c0.address(), *c0.address()),
//         ]),
//         /* type origin */
//         HashMap::from_iter([
//             ((c0.clone(), ident_str!("S").to_owned()), c0.clone()),
//             ((b0.clone(), ident_str!("S").to_owned()), b1.clone()),
//         ]),
//     );
//     adapter.publish_modules(b1_modules);
//
//     // This call should fail to load the module and rollback cleanly
//     adapter.call_function_with_error(&b0, ident_str!("b"));
//
//     // Restore old behavior of failpoint
//     fail::cfg("verifier-failpoint-4", "off").unwrap();
// }

#[test]
fn publish_bundle_and_load() {
    let data_store = InMemoryStorage::new();
    let adapter = Adapter::new(data_store);

    let a0 = ModuleId::new(ADDR4, ident_str!("a").to_owned());
    let c1_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v1", []).unwrap();
    let b0_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v0", ["c_v0"]).unwrap();
    let a0_modules = get_relinker_tests_modules_with_deps(ADDR4, "a_v0", ["b_v0", "c_v1"]).unwrap();

    adapter
        .linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new())
        .publish_modules(c1_modules);

    adapter
        .linkage(
            ADDR3,
            HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
            HashMap::new(),
        )
        .publish_modules(b0_modules);

    let mut adapter = adapter.linkage(
        ADDR4,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3), (ADDR4, ADDR4)]),
        HashMap::new(),
    );
    adapter.publish_modules(a0_modules);

    assert_eq!(
        vec![MoveValue::U64(44 + 43 + 1)],
        adapter.call_function_with_return(&a0, ident_str!("a")),
    );
}

#[test]
fn publish_bundle_with_err_retry() {
    let data_store = InMemoryStorage::new();
    let adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let a0 = ModuleId::new(ADDR4, ident_str!("a").to_owned());
    let c0_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v0", []).unwrap();
    let c1_modules = get_relinker_tests_modules_with_deps(ADDR2, "c_v1", []).unwrap();
    let b0_modules = get_relinker_tests_modules_with_deps(ADDR3, "b_v0", ["c_v0"]).unwrap();
    let a0_modules = get_relinker_tests_modules_with_deps(ADDR4, "a_v0", ["b_v0", "c_v1"]).unwrap();

    adapter
        .linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new())
        .publish_modules(c0_modules);

    adapter
        .linkage(
            ADDR3,
            HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
            HashMap::new(),
        )
        .publish_modules(b0_modules);

    // Publishing the bundle should fail, because `a0` should not link with `c0`.
    adapter
        .linkage(
            ADDR4,
            HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3), (ADDR4, ADDR4)]),
            HashMap::new(),
        )
        .publish_modules_with_error(a0_modules.clone());

    // publish the upgrade of c0 to ADDR5
    adapter
        .linkage(ADDR5, HashMap::from([(ADDR2, ADDR5)]), HashMap::new())
        .publish_modules(c1_modules);

    let mut adapter = adapter.linkage(
        ADDR4,
        HashMap::from([(ADDR2, ADDR5), (ADDR3, ADDR3), (ADDR4, ADDR4)]),
        HashMap::new(),
    );

    // Try again and everything should publish successfully (in particular, the failed publish
    // will not leave behind modules in the loader).
    adapter.publish_modules(a0_modules);

    assert_eq!(
        vec![MoveValue::U64(44 + 43 + 1)],
        adapter.call_function_with_return(&a0, ident_str!("a")),
    );
}

#[test]
fn deep_dependency_list_0() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a chain of dependencies
    let max = 350u64;
    dependency_chain(1, max, &mut modules);
    adapter.publish_modules(modules);

    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = format!("A{}", max);
    let dep_name = format!("A{}", max - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR3, name, (ADDR2, deps));
    adapter.publish_modules(vec![module]);
}

#[test]
fn deep_dependency_list_1() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a chain of dependencies
    let max = 101u64;
    dependency_chain(1, max, &mut modules);
    adapter.publish_modules(modules);

    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = format!("A{}", max);
    let dep_name = format!("A{}", max - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR3, name, (ADDR2, deps));
    adapter.publish_modules(vec![module]);
}

#[test]
fn deep_dependency_list_ok_0() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a chain of dependencies
    let max = 100u64;
    dependency_chain(1, max, &mut modules);
    adapter.publish_modules(modules);

    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = format!("A{}", max);
    let dep_name = format!("A{}", max - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR3, name, (ADDR2, deps));
    adapter.publish_modules(vec![module]);
}

#[test]
fn deep_dependency_list_ok_1() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a chain of dependencies
    let max = 30u64;
    dependency_chain(1, max, &mut modules);
    adapter.publish_modules(modules);

    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = format!("A{}", max);
    let dep_name = format!("A{}", max - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR2, name, (ADDR2, deps));
    adapter.publish_modules(vec![module]);
}

#[test]
fn deep_dependency_tree_0() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a tree of dependencies
    let width = 5u64;
    let height = 101u64;
    dependency_tree(width, height, &mut modules);
    adapter.publish_modules(modules);

    // use one of the module in the tree
    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = "ASome".to_string();
    let dep_name = format!("A_{}_{}", height - 1, width - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR2, name, (ADDR2, deps));
    adapter.publish_module_bundle(vec![module]);
}

#[test]
fn deep_dependency_tree_1() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a tree of dependencies
    let width = 3u64;
    let height = 350u64;
    dependency_tree(width, height, &mut modules);
    adapter.publish_modules(modules);

    // use one of the module in the tree
    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = "ASome".to_string();
    let dep_name = format!("A_{}_{}", height - 1, width - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR2, name, (ADDR2, deps));
    adapter.publish_module_bundle(vec![module]);
}

#[test]
fn deep_dependency_tree_ok_0() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a tree of dependencies
    let width = 10u64;
    let height = 20u64;
    dependency_tree(width, height, &mut modules);
    adapter.publish_modules(modules);

    // use one of the module in the tree
    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = "ASome".to_string();
    let dep_name = format!("A_{}_{}", height - 1, width - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR2, name, (ADDR2, deps));
    adapter.publish_modules(vec![module]);
}

#[test]
fn deep_dependency_tree_ok_1() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a tree of dependencies
    let width = 3u64;
    let height = 100u64;
    dependency_tree(width, height, &mut modules);
    adapter.publish_modules(modules);

    // use one of the module in the tree
    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = "ASome".to_string();
    let dep_name = format!("A_{}_{}", height - 1, width - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_dependencies(ADDR2, name, (ADDR2, deps));
    adapter.publish_modules(vec![module]);
}

#[test]
fn deep_friend_list_ok_0() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a chain of dependencies
    let max = 100u64;
    friend_chain(1, max, &mut modules);
    adapter.publish_modules(modules);

    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = format!("A{}", max);
    let dep_name = format!("A{}", max - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_friends(name, deps);
    adapter.publish_modules(vec![module]);
}

#[test]
fn deep_friend_list_ok_1() {
    let data_store = InMemoryStorage::new();
    let mut adapter =
        Adapter::new(data_store).linkage(ADDR2, HashMap::from([(ADDR2, ADDR2)]), HashMap::new());

    let mut modules = vec![];

    // create a chain of dependencies
    let max = 30u64;
    friend_chain(1, max, &mut modules);
    adapter.publish_modules(modules);

    let mut adapter = adapter.linkage(
        ADDR3,
        HashMap::from([(ADDR2, ADDR2), (ADDR3, ADDR3)]),
        HashMap::new(),
    );
    let name = format!("A{}", max);
    let dep_name = format!("A{}", max - 1);
    let deps = vec![dep_name];
    let module = empty_module_with_friends(name, deps);
    adapter.publish_modules(vec![module]);
}

fn leaf_module(name: &str) -> CompiledModule {
    let mut module = empty_module();
    module.identifiers[0] = Identifier::new(name).unwrap();
    module.address_identifiers[0] = ADDR2;
    module
}

// Create a list of dependent modules
fn dependency_chain(start: u64, end: u64, modules: &mut Vec<CompiledModule>) {
    let module = leaf_module("A0");
    modules.push(module);

    for i in start..end {
        let name = format!("A{}", i);
        let dep_name = format!("A{}", i - 1);
        let deps = vec![dep_name];
        let module = empty_module_with_dependencies(ADDR2, name, (ADDR2, deps));
        modules.push(module);
    }
}

// Create a tree (well a forest or DAG really) of dependent modules
fn dependency_tree(width: u64, height: u64, modules: &mut Vec<CompiledModule>) {
    let mut deps = vec![];
    for i in 0..width {
        let name = format!("A_{}_{}", 0, i);
        let module = leaf_module(name.as_str());
        deps.push(name);
        modules.push(module);
    }
    for i in 1..height {
        let mut new_deps = vec![];
        for j in 0..width {
            let name = format!("A_{}_{}", i, j);
            let module = empty_module_with_dependencies(ADDR2, name.clone(), (ADDR2, deps.clone()));
            new_deps.push(name);
            modules.push(module);
        }
        deps = new_deps;
    }
}

// Create a module that uses (depends on) the list of given modules
fn empty_module_with_dependencies(
    address: PackageStorageId,
    name: String,
    deps: (PackageStorageId, Vec<String>),
) -> CompiledModule {
    let mut module = empty_module();
    module.address_identifiers[0] = address;
    module.identifiers[0] = Identifier::new(name).unwrap();
    let idx = if address == deps.0 {
        0
    } else {
        module.address_identifiers.push(deps.0);
        1
    };
    for dep in deps.1 {
        module.identifiers.push(Identifier::new(dep).unwrap());
        module.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(idx),
            name: IdentifierIndex((module.identifiers.len() - 1) as TableIndex),
        });
    }
    module
}

// Create a list of friends modules
fn friend_chain(start: u64, end: u64, modules: &mut Vec<CompiledModule>) {
    let module = leaf_module("A0");
    modules.push(module);

    for i in start..end {
        let name = format!("A{}", i);
        let dep_name = format!("A{}", i - 1);
        let deps = vec![dep_name];
        let module = empty_module_with_friends(name, deps);
        modules.push(module);
    }
}

// Create a module that uses (friends on) the list of given modules
fn empty_module_with_friends(name: String, deps: Vec<String>) -> CompiledModule {
    let mut module = empty_module();
    module.address_identifiers[0] = ADDR2;
    module.identifiers[0] = Identifier::new(name).unwrap();
    for dep in deps {
        module.identifiers.push(Identifier::new(dep).unwrap());
        module.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex((module.identifiers.len() - 1) as TableIndex),
        });
    }
    module
}