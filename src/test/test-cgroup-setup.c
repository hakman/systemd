/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"

TEST(cg_create) {
        int r;

        _cleanup_free_ char *here = NULL;
        ASSERT_OK(cg_pid_get_path_shifted(0, NULL, &here));

        /* cg_* will use path_simplify(), so use it here too otherwise when running in a container at the
         * root it asserts with "/test-b != //test-b" */
        _cleanup_free_ char *test_a = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-a"))),
                            *test_b = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b"))),
                            *test_c = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b/test-c"))),
                            *test_d = ASSERT_NOT_NULL(path_simplify(path_join(here, "/test-b/test-d")));
        char *path;

        log_info("Paths for test:\n%s\n%s", test_a, test_b);

        /* Possibly clean up left-overs from aborted previous runs */
        (void) cg_trim(test_a, /* delete_root= */ true);
        (void) cg_trim(test_b, /* delete_root= */ true);

        r = cg_create(test_a);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(r) || r == -ENOENT)
                return (void) log_tests_skipped_errno(r, "%s: Failed to create cgroup %s", __func__, test_a);

        ASSERT_OK_EQ(r, 1);
        ASSERT_OK_ZERO(cg_create(test_a));
        ASSERT_OK_EQ(cg_create(test_b), 1);
        ASSERT_OK_EQ(cg_create(test_c), 1);
        ASSERT_OK_ZERO(cg_create_and_attach(test_b, 0));

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_STREQ(path, test_b);
        free(path);

        ASSERT_OK_ZERO(cg_attach(test_a, 0));

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_a));
        free(path);

        ASSERT_OK_EQ(cg_create_and_attach(test_d, 0), 1);

        ASSERT_OK_ZERO(cg_pid_get_path(getpid_cached(), &path));
        ASSERT_TRUE(path_equal(path, test_d));
        free(path);

        ASSERT_OK_ZERO(cg_get_path(test_d, /* suffix= */ NULL, &path));
        log_debug("test_d: %s", path);
        ASSERT_TRUE(path_equal(path, strjoina("/sys/fs/cgroup", test_d)));
        free(path);

        ASSERT_OK_POSITIVE(cg_is_empty(test_a));
        ASSERT_OK_ZERO(cg_is_empty(test_b));

        ASSERT_OK_ZERO(cg_kill_recursive(test_a, 0, 0, NULL, NULL, NULL));
        ASSERT_OK_POSITIVE(cg_kill_recursive(test_b, 0, 0, NULL, NULL, NULL));

        ASSERT_OK(cg_trim(test_a, true));
        ASSERT_ERROR(cg_trim(test_b, true), EBUSY);

        ASSERT_OK_ZERO(cg_attach(here, 0));
        ASSERT_OK(cg_trim(test_b, true));
}

TEST_RET(cg_enable) {
        _cleanup_free_ char *here = NULL, *parent = NULL, *group = NULL, *child = NULL, *controllers = NULL;
        CGroupMask supported, mask, result, actual;
        int r;

        /* Use a sibling when possible: a non-root cgroup with processes cannot enable domain controllers. */
        ASSERT_OK(cg_pid_get_path_shifted(0, /* root= */ NULL, &here));
        if (path_equal(here, "/"))
                parent = ASSERT_NOT_NULL(strdup("/"));
        else
                ASSERT_OK(path_extract_directory(here, &parent));
        group = ASSERT_NOT_NULL(path_join(parent, "test-cgroup-enable"));
        child = ASSERT_NOT_NULL(path_join(group, "child"));

        (void) cg_trim(group, /* delete_root= */ true);
        r = cg_create(group);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(r) || r == -ENOENT)
                return log_tests_skipped_errno(r, "Cannot create test cgroup");
        ASSERT_OK(r);
        ASSERT_OK(cg_mask_supported_subtree(group, &supported));
        mask = supported & CGROUP_MASK_MEMORY ?: supported & CGROUP_MASK_PIDS;
        if (mask == 0) {
                ASSERT_OK(cg_trim(group, /* delete_root= */ true));
                return log_tests_skipped("Neither memory nor pids controller is available");
        }

        /* A failed state read must fall back to the write path, preserving its error contract. */
        result = _CGROUP_MASK_ALL;
        ASSERT_ERROR(cg_enable(supported, mask, child, &result), ENOENT);
        ASSERT_EQ(result, (CGroupMask) _CGROUP_MASK_ALL);

        ASSERT_OK(cg_enable(supported, mask, group, &result));
        ASSERT_EQ(result, mask);
        /* Check the result contract for an unchanged request; both the read and write paths must satisfy it. */
        ASSERT_OK(cg_enable(supported, mask, group, &result));
        ASSERT_EQ(result, mask);
        ASSERT_OK(cg_get_attribute(group, "cgroup.subtree_control", &controllers));
        ASSERT_OK(cg_mask_from_string(controllers, &actual));
        ASSERT_EQ(actual & supported & CGROUP_MASK_V2, mask);

        ASSERT_OK(cg_create(child));
        ASSERT_OK(cg_enable(supported, mask, child, &result));
        ASSERT_EQ(result, mask);
        /* A failed parent disable must report the controller still enabled, so callers can retry. */
        ASSERT_OK(cg_enable(supported, 0, group, &result));
        ASSERT_EQ(result, mask);
        ASSERT_OK(cg_enable(supported, 0, child, &result));
        ASSERT_EQ(result, (CGroupMask) 0);
        ASSERT_OK(cg_enable(supported, 0, group, &result));
        ASSERT_EQ(result, (CGroupMask) 0);
        ASSERT_OK(cg_enable(supported, 0, group, &result));
        ASSERT_EQ(result, (CGroupMask) 0);

        ASSERT_OK(cg_trim(group, /* delete_root= */ true));
        return 0;
}

static int intro(void) {
        if (cg_is_available() <= 0)
                return log_tests_skipped("cgroupfs v2 is not mounted");

        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
