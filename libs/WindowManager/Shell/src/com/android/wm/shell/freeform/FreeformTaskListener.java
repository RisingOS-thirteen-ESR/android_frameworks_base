/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.wm.shell.freeform;

import static com.android.wm.shell.ShellTaskOrganizer.TASK_LISTENER_TYPE_FREEFORM;

import android.app.ActivityManager.RunningTaskInfo;
import android.util.SparseArray;
import android.view.SurfaceControl;

import com.android.internal.protolog.common.ProtoLog;
import com.android.wm.shell.ShellTaskOrganizer;
import com.android.wm.shell.desktopmode.DesktopModeStatus;
import com.android.wm.shell.desktopmode.DesktopModeTaskRepository;
import com.android.wm.shell.protolog.ShellProtoLogGroup;
import com.android.wm.shell.sysui.ShellInit;
import com.android.wm.shell.transition.Transitions;
import com.android.wm.shell.windowdecor.WindowDecorViewModel;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * {@link ShellTaskOrganizer.TaskListener} for {@link
 * ShellTaskOrganizer#TASK_LISTENER_TYPE_FREEFORM}.
 */
public class FreeformTaskListener implements ShellTaskOrganizer.TaskListener,
        ShellTaskOrganizer.FocusListener {
    private static final String TAG = "FreeformTaskListener";

    private final ShellTaskOrganizer mShellTaskOrganizer;
    private final Optional<DesktopModeTaskRepository> mDesktopModeTaskRepository;
    private final WindowDecorViewModel mWindowDecorationViewModel;

    private final SparseArray<State> mTasks = new SparseArray<>();
    private final List<FreeformListener> mListeners = new ArrayList<>();

    private static class State {
        RunningTaskInfo mTaskInfo;
        SurfaceControl mLeash;
    }

    public FreeformTaskListener(
            ShellInit shellInit,
            ShellTaskOrganizer shellTaskOrganizer,
            Optional<DesktopModeTaskRepository> desktopModeTaskRepository,
            WindowDecorViewModel windowDecorationViewModel) {
        mShellTaskOrganizer = shellTaskOrganizer;
        mWindowDecorationViewModel = windowDecorationViewModel;
        mDesktopModeTaskRepository = desktopModeTaskRepository;
        if (shellInit != null) {
            shellInit.addInitCallback(this::onInit, this);
        }
    }

    private void onInit() {
        mShellTaskOrganizer.addListenerForType(this, TASK_LISTENER_TYPE_FREEFORM);
        if (DesktopModeStatus.isAnyEnabled()) {
            mShellTaskOrganizer.addFocusListener(this);
        }
    }

    void registerFreeformListener(FreeformListener listener) {
        if (mListeners.contains(listener)) return;
        mListeners.add(listener);
        // Send the current status upon registration.
        sendStatusToListener(listener);
    }

    void unregisterFreeformListener(FreeformListener listener) {
        mListeners.remove(listener);
    }

    private void sendStatusToListener(FreeformListener listener) {
        for (int i = 0; i < mTasks.size(); i++) {
            listener.onTaskEnteredFreeform(mTasks.valueAt(i).mTaskInfo);
        }
    }

    private void sendOnTaskEnteredFreeform(RunningTaskInfo taskInfo) {
        for (int i = mListeners.size() - 1; i >= 0; --i) {
            final FreeformListener listener = mListeners.get(i);
            listener.onTaskEnteredFreeform(taskInfo);
        }
    }

    private void sendOnTaskExitedFreeform(RunningTaskInfo taskInfo) {
        for (int i = mListeners.size() - 1; i >= 0; --i) {
            final FreeformListener listener = mListeners.get(i);
            listener.onTaskExitedFreeform(taskInfo);
        }
    }

    @Override
    public void onTaskAppeared(RunningTaskInfo taskInfo, SurfaceControl leash) {
        if (mTasks.get(taskInfo.taskId) != null) {
            throw new IllegalStateException("Task appeared more than once: #" + taskInfo.taskId);
        }
        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_TASK_ORG, "Freeform Task Appeared: #%d",
                taskInfo.taskId);
        final State state = new State();
        state.mTaskInfo = taskInfo;
        state.mLeash = leash;
        mTasks.put(taskInfo.taskId, state);
        if (!Transitions.ENABLE_SHELL_TRANSITIONS) {
            SurfaceControl.Transaction t = new SurfaceControl.Transaction();
            mWindowDecorationViewModel.onTaskOpening(taskInfo, leash, t, t);
            t.apply();
        }

        if (DesktopModeStatus.isAnyEnabled()) {
            mDesktopModeTaskRepository.ifPresent(repository -> {
                repository.addOrMoveFreeformTaskToTop(taskInfo.taskId);
                if (taskInfo.isVisible) {
                    if (repository.addActiveTask(taskInfo.taskId)) {
                        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DESKTOP_MODE,
                                "Adding active freeform task: #%d", taskInfo.taskId);
                    }
                    repository.updateVisibleFreeformTasks(taskInfo.taskId, true);
                }
            });
        }

        sendOnTaskEnteredFreeform(taskInfo);
    }

    @Override
    public void onTaskVanished(RunningTaskInfo taskInfo) {
        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_TASK_ORG, "Freeform Task Vanished: #%d",
                taskInfo.taskId);
        mTasks.remove(taskInfo.taskId);

        if (DesktopModeStatus.isAnyEnabled()) {
            mDesktopModeTaskRepository.ifPresent(repository -> {
                repository.removeFreeformTask(taskInfo.taskId);
                if (repository.removeActiveTask(taskInfo.taskId)) {
                    ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DESKTOP_MODE,
                            "Removing active freeform task: #%d", taskInfo.taskId);
                }
                repository.updateVisibleFreeformTasks(taskInfo.taskId, false);
            });
        }

        if (!Transitions.ENABLE_SHELL_TRANSITIONS) {
            mWindowDecorationViewModel.destroyWindowDecoration(taskInfo);
        }

        sendOnTaskExitedFreeform(taskInfo);
    }

    @Override
    public void onTaskInfoChanged(RunningTaskInfo taskInfo) {
        final State state = mTasks.get(taskInfo.taskId);

        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_TASK_ORG, "Freeform Task Info Changed: #%d",
                taskInfo.taskId);
        mWindowDecorationViewModel.onTaskInfoChanged(taskInfo);
        state.mTaskInfo = taskInfo;
        if (DesktopModeStatus.isAnyEnabled()) {
            mDesktopModeTaskRepository.ifPresent(repository -> {
                if (taskInfo.isVisible) {
                    if (repository.addActiveTask(taskInfo.taskId)) {
                        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_DESKTOP_MODE,
                                "Adding active freeform task: #%d", taskInfo.taskId);
                    }
                }
                repository.updateVisibleFreeformTasks(taskInfo.taskId, taskInfo.isVisible);
            });
        }
    }

    @Override
    public void onFocusTaskChanged(RunningTaskInfo taskInfo) {
        ProtoLog.v(ShellProtoLogGroup.WM_SHELL_TASK_ORG,
                "Freeform Task Focus Changed: #%d focused=%b",
                taskInfo.taskId, taskInfo.isFocused);
        if (DesktopModeStatus.isAnyEnabled() && taskInfo.isFocused) {
            mDesktopModeTaskRepository.ifPresent(repository -> {
                repository.addOrMoveFreeformTaskToTop(taskInfo.taskId);
            });
        }
    }

    @Override
    public void attachChildSurfaceToTask(int taskId, SurfaceControl.Builder b) {
        b.setParent(findTaskSurface(taskId));
    }

    @Override
    public void reparentChildSurfaceToTask(int taskId, SurfaceControl sc,
            SurfaceControl.Transaction t) {
        t.reparent(sc, findTaskSurface(taskId));
    }

    private SurfaceControl findTaskSurface(int taskId) {
        if (!mTasks.contains(taskId)) {
            throw new IllegalArgumentException("There is no surface for taskId=" + taskId);
        }
        return mTasks.get(taskId).mLeash;
    }

    @Override
    public void dump(PrintWriter pw, String prefix) {
        final String innerPrefix = prefix + "  ";
        pw.println(prefix + this);
        pw.println(innerPrefix + mTasks.size() + " tasks");
    }

    @Override
    public String toString() {
        return TAG;
    }
}
