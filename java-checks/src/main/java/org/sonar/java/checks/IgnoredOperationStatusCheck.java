/*
 * SonarQube Java
 * Copyright (C) 2012-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.java.checks;

import org.sonar.check.Rule;
import org.sonar.java.checks.methods.AbstractMethodDetection;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

@Rule(key = "S899")
public class IgnoredOperationStatusCheck extends AbstractMethodDetection {

  private static final String FILE = "java.io.File";
  private static final String CONDITION = "java.util.concurrent.locks.Condition";
  private static final String BLOCKING_QUEUE = "java.util.concurrent.BlockingQueue";

  @Override
  protected MethodMatchers getMethodInvocationMatchers() {
    return MethodMatchers.or(
      MethodMatchers.create().ofSubType("java.util.concurrent.locks.Lock").name("tryLock").withoutParameters(),
      MethodMatchers.create().ofType(FILE).withoutParameters()
        .name("delete")
        .name("exists")
        .name("createNewFile")
        .startWithName("can")
        .startWithName("is"),

      MethodMatchers.create().ofType(FILE).withAnyParameters()
        .startWithName("set"),

      MethodMatchers.create().ofType(FILE).name("renameTo").withParameters(FILE),

      MethodMatchers.create().ofSubType("java.util.Iterator").name("hasNext").withoutParameters(),
      MethodMatchers.create().ofSubType("java.util.Enumeration").name("hasMoreElements").withoutParameters(),

      MethodMatchers.create().ofSubType(CONDITION).name("await").withParameters("long", "java.util.concurrent.TimeUnit"),
      MethodMatchers.create().ofSubType(CONDITION).name("awaitUntil").withParameters("java.util.Date"),
      MethodMatchers.create().ofSubType(CONDITION).name("awaitNanos").withParameters("long"),

      MethodMatchers.create().ofType("java.util.concurrent.CountDownLatch").name("await").withParameters("long", "java.util.concurrent.TimeUnit"),
      MethodMatchers.create().ofType("java.util.concurrent.Semaphore").name("tryAcquire").withAnyParameters(),

      MethodMatchers.create().ofSubType(BLOCKING_QUEUE).name("offer").withAnyParameters(),
      MethodMatchers.create().ofSubType(BLOCKING_QUEUE).name("remove").withAnyParameters());
  }

  @Override
  protected void onMethodInvocationFound(MethodInvocationTree mit) {
    Tree parent = mit.parent();
    if (parent.is(Tree.Kind.EXPRESSION_STATEMENT)
      || (parent.is(Tree.Kind.VARIABLE) && ((VariableTree) parent).symbol().usages().isEmpty())) {
      reportIssue(parent, "Do something with the \"" + mit.symbolType().name() + "\" value returned by \"" + mit.symbol().name() + "\".");
    }
  }

}
