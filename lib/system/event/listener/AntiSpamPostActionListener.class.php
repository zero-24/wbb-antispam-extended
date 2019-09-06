<?php
/**
 * @package     zero-24.antispam.extended
 * @copyright   Copyright (C) 2005 - 2019 Tobias Zulauf (https://forum.joomla.de). All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
namespace wbb\system\event\listener;

use wcf\system\event\listener\IParameterizedEventListener;
use wcf\system\WCF;

/**
 * Anti Spam Extended Listener
 *
 * @since  1.0.0
 */
class AntiSpamPostActionListener implements IParameterizedEventListener
{
	/**
	 * Whitelisted chars that should be excluded from the checks
	 *
	 * @var     array
	 * @since   1.0.0
	 */
	private $globalWitelistedChars = [
		'ß',
		'ä',
		'ü',
		'ö',
		'´',
		'€',
		'°',
		'“',
		'„',
		'–',
	];

	/**
	 * Make sure we only run our checks once
	 *
	 * @var     array
	 * @since   1.0.3
	 */
	private $objectsChecked = [];

	/**
	 * The Event Listener execute method that handles the checks
	 *
	 * @param   object   $eventObj    The event object
	 * @param   string   $className   The classname
	 * @param   string   $eventName   The event name
	 * @param   array    $parameters  The event parameters array
	 *
	 * @return  void
	 *
	 * @see     \wcf\system\event\listener\IParameterizedEventListener::execute()
	 * @since   1.0.0
	 */
	public function execute($eventObj, $className, $eventName, array &$parameters)
	{
		$actionName = $eventObj->getActionName();
		$parameters = $eventObj->getParameters();

		if (in_array($actionName, ['triggerPublication', 'update']))
		{
			foreach ($eventObj->getObjects() as $object)
			{
				$objectId = $object->getObjectID();

				// Early exit in the case that we already checked this item
				if (isset($this->objectsChecked[$objectId]) && $this->objectsChecked[$objectId])
				{
					continue;
				}

				// Mark this objectId as checked
				$this->objectsChecked[$objectId] = true;

				// Make sure the execution is not disabled
				if ($object->isDisabled
					|| !POST_ANTISPAMEXTENDED_ENABLE
					|| WCF::getSession()->getPermission('user.board.canBypassAntiSpamExtended'))
				{
					continue;
				}

				/**
				 * Make sure the user passes the min_post option and also make
				 * sure the checks are enforced anyway when the value is set to 0
				 */
				if (WCF::getUser()->wbbPosts >= POST_ANTISPAMEXTENDED_MIN_POSTS
					&& POST_ANTISPAMEXTENDED_MIN_POSTS >= 1)
				{
					continue;
				}

				// On update we should get the message passed as parameter
				if (isset($parameters['data']['message'])
					&& !empty($parameters['data']['message']))
				{
					$content = $parameters['data']['message'];
				}
				else
				{
					$content = $object->getMessage();
				}

				// On update we should get the title passed as parameter
				if (isset($parameters['data']['subject'])
					&& !empty($parameters['data']['subject']))
				{
					$title = $parameters['data']['subject'];
				}
				else
				{
					$title = $object->getTitle();
				}

				if ($this->checkContent($content) || $this->checkContent($title))
				{
					// When this is the first post or we edit an post we should only disable it
					if (isset($parameters['isFirstPost'])
						&& $parameters['isFirstPost'] === true
						|| $actionName === 'update')
					{
						(new \wbb\data\post\PostAction([$object], 'disable'))->executeAction();

						continue;
					}

					// When it is not we can also delete it
					switch (POST_ANTISPAMEXTENDED_ACTION)
					{
						case 'delete':
							(new \wbb\data\post\PostAction([$object], 'delete'))->executeAction();
							break;

						case 'trash':
							(new \wbb\data\post\PostAction([$object], 'trash'))->executeAction();
							break;

						case 'disable':
						default:
							(new \wbb\data\post\PostAction([$object], 'disable'))->executeAction();
							break;
					}
				}
			}
		}
	}

	/**
	 * Parses the content and return true whether the post should be blocked
	 *
	 * @param   string   $text  The text to be parsed
	 *
	 * @return  boolean  True whether the post should be blocked
	 *
	 * @since   1.0.0
	 */
	private function checkContent($text): bool
	{
		$whitelistedChars = explode(',', POST_ANTISPAMEXTENDED_WHITELIST);
		$whitelistedChars = array_merge($whitelistedChars, $this->globalWitelistedChars);

		// Make sure the whitelisted chars does not trigger the checker
		foreach ($whitelistedChars as $whitelistedChar)
		{
			$text = str_replace($whitelistedChar, '', $text);

			$whitelistedChar = mb_strtoupper($whitelistedChar, 'UTF-8');
			$text = str_replace($whitelistedChar, '', $text);
		}

		$clearstring = filter_var($text, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_HIGH);

		if ($clearstring != $text)
		{
			return true;
		}

		return false;
	}
}
