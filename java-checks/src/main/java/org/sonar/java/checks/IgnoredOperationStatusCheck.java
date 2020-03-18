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
import org.sonar.java.matcher.MethodMatcher;
import org.sonar.java.matcher.NameCriteria;
import org.sonar.java.matcher.TypeCriteria;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

@Rule(key = "S899")
public class IgnoredOperationStatusCheck extends AbstractMethodDetection {

  private static final String FILE = "java.io.File";
  private static final TypeCriteria SUBTYPE_OF_CONDITION = TypeCriteria.subtypeOf("java.util.concurrent.locks.Condition");
  private static final TypeCriteria SUBTYPE_OF_BLOCKING_QUEUE = TypeCriteria.subtypeOf("java.util.concurrent.BlockingQueue");

  @Override
  protected MethodMatchers getMethodInvocationMatchers() {
    return MethodMatchers.or(
      MethodMatcher.create().ofType(TypeCriteria.subtypeOf("java.util.concurrent.locks.Lock")).name("tryLock").withoutParameters(),

      MethodMatcher.create().ofType(FILE).name("delete").withoutParameters(),
      MethodMatcher.create().ofType(FILE).name("exists").withoutParameters(),
      MethodMatcher.create().ofType(FILE).name("createNewFile").withoutParameters(),
      MethodMatcher.create().ofType(FILE).name("renameTo").addParameter(FILE),
      MethodMatcher.create().ofType(FILE).name(NameCriteria.startsWith("can")).withoutParameters(),
      MethodMatcher.create().ofType(FILE).name(NameCriteria.startsWith("is")).withoutParameters(),
      MethodMatcher.create().ofType(FILE).name(NameCriteria.startsWith("set")).withAnyParameters(),

      MethodMatcher.create().ofType(TypeCriteria.subtypeOf("java.util.Iterator")).name("hasNext").withoutParameters(),
      MethodMatcher.create().ofType(TypeCriteria.subtypeOf("java.util.Enumeration")).name("hasMoreElements").withoutParameters(),

      MethodMatcher.create().ofType(SUBTYPE_OF_CONDITION).name("await").addParameter("long").addParameter("java.util.concurrent.TimeUnit"),
      MethodMatcher.create().ofType(SUBTYPE_OF_CONDITION).name("awaitUntil").addParameter("java.util.Date"),
      MethodMatcher.create().ofType(SUBTYPE_OF_CONDITION).name("awaitNanos").addParameter("long"),

      MethodMatcher.create().ofType("java.util.concurrent.CountDownLatch").name("await").addParameter("long").addParameter("java.util.concurrent.TimeUnit"),
      MethodMatcher.create().ofType("java.util.concurrent.Semaphore").name("tryAcquire").withAnyParameters(),

      MethodMatcher.create().ofType(SUBTYPE_OF_BLOCKING_QUEUE).name("offer").withAnyParameters(),
      MethodMatcher.create().ofType(SUBTYPE_OF_BLOCKING_QUEUE).name("remove").withAnyParameters());
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
